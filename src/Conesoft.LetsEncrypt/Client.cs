using Certes;
using Certes.Acme;
using Conesoft.DNSimple;
using Conesoft.Files;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace Conesoft.LetsEncrypt
{
    public class Client
    {
        readonly string mail;
        readonly bool production;
        readonly Func<HttpClient> httpClientGenerator;
        readonly string dnsimpleToken;
        readonly Directory rootPath;
        AcmeContext? acme;

        Uri Server => production ? WellKnownServers.LetsEncryptV2 : WellKnownServers.LetsEncryptStagingV2;

        public Client(string mail, Func<HttpClient> httpClientGenerator, string dnsimpleToken, bool production = true)
        {
            this.mail = mail;
            this.production = production;
            this.httpClientGenerator = httpClientGenerator;
            this.dnsimpleToken = dnsimpleToken;
            this.rootPath = Directory.From(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)) / "Conesoft.LetsEncrypt";
        }

        public async Task<string> CreateWildcardCertificateFor(string domain, string certificatePassword, CertificateInformation information)
        {
            await Login();
            var order = await acme!.NewOrder(new[] { domain, $"*.{domain}" });
            var authorizations = (await order.Authorizations()).ToArray();
            var challenges = await Task.WhenAll(authorizations.Select(async a => await a.Dns()));

            await UpdateDns(domain, (domain, index) => acme.AccountKey.DnsTxt(challenges[index].Token));

            var results = await Task.WhenAll(challenges.Select(async c => await c.Validate()));

            await Task.Delay(TimeSpan.FromSeconds(5));

            var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
            var certificate = await order.Generate(new CsrInfo
            {
                CountryName = information.CountryName,
                State = information.State,
                Locality = information.Locality,
                Organization = information.Organization,
                OrganizationUnit = information.OrganizationUnit,
                CommonName = domain
            }, privateKey);

            var certificateFile = rootPath / "Certificates" / (production ? "Production" : "Development") / File.Name(domain, "pfx");

            var pfx = certificate.ToPfx(privateKey).Build(domain, certificatePassword);

            await certificateFile.WriteBytes(pfx);

            return certificateFile.Path;
        }

        async Task Login()
        {
            if (this.acme == null)
            {
                var acmeHttpClient = new AcmeHttpClient(Server, httpClientGenerator());

                var accountFile = rootPath / "Account" / (production ? "Production" : "Development") / File.Name(mail, "pem");

                if (accountFile.Exists == false)
                {
                    this.acme = new AcmeContext(Server, null, acmeHttpClient);
                    await acme.NewAccount(mail, true);

                    await accountFile.WriteText(acme.AccountKey.ToPem());
                }
                else
                {
                    this.acme = new AcmeContext(Server, KeyFactory.FromPem(await accountFile.ReadText()), acmeHttpClient);
                }
            }
        }

        async Task UpdateDns(string domain, Func<string, int, string> challenge)
        {
            var dnsimple = new DNSimple.Client(httpClientGenerator());

            dnsimple.UseToken(dnsimpleToken);
            var dnsimpleAccount = await dnsimple.GetAccount(mail);
            var zone = await dnsimpleAccount.GetZone(domain);

            var records = (await zone.GetRecords()).Where(r => r.Type == RecordType.TXT.Type).ToArray();

            for (var i = 0; i < 2; i++)
            {
                var record = records[i];

                await record.UpdateContent(challenge(domain, i));
            }
        }
    }
}