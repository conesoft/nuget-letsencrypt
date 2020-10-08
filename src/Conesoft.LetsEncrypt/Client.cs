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
        const string acmeChallengeDnsName = "_acme-challenge";

        readonly string mail;
        readonly bool production;
        readonly Func<HttpClient> httpClientGenerator;

        readonly string dnsimpleToken;
        readonly Directory rootPath;
        AcmeContext? acme;
        Account? dnsimple;

        Uri Server => production ? WellKnownServers.LetsEncryptV2 : WellKnownServers.LetsEncryptStagingV2;

        public Client(string mail, Func<HttpClient> httpClientGenerator, string dnsimpleToken, bool production = true)
        {
            this.mail = mail;
            this.production = production;
            this.httpClientGenerator = httpClientGenerator;
            this.dnsimpleToken = dnsimpleToken;
            this.rootPath = Directory.From(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)) / "Conesoft.LetsEncrypt";
        }

        public async Task<byte[]> CreateWildcardCertificateFor(string[] domains, string certificatePassword, CertificateInformation information)
        {
            await Login();

            var order = await acme!.NewOrder(domains.SelectMany(domain => new[] { domain, $"*.{domain}" }).ToArray());

            var authorizations = (await order.Authorizations()).ToArray();

            var challenges = await Task.WhenAll(authorizations.Select(async a => await a.Dns()));

            await AddDnsChallenges(domains, challenges.Select(challenge => acme.AccountKey.DnsTxt(challenge.Token)).ToArray());

            await Task.Delay(TimeSpan.FromSeconds(1));

            var results = await Task.WhenAll(challenges.Select(async c => await c.Validate()));

            await CleanupDnsChallenges(domains);
            
            var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);

            var certificate = await order.Generate(new CsrInfo
            {
                CountryName = information.CountryName,
                State = information.State,
                Locality = information.Locality,
                Organization = information.Organization,
                OrganizationUnit = information.OrganizationUnit,
                CommonName = domains.First()
            }, privateKey);

            var pfx = certificate.ToPfx(privateKey).Build(string.Join(' ', domains), certificatePassword);

            return pfx;
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
            if(this.dnsimple == null)
            {
                var client = new DNSimple.Client(httpClientGenerator());

                client.UseToken(dnsimpleToken);

                this.dnsimple = await client.GetAccount(mail);
            }
        }

        async Task AddDnsChallenges(string[] domains, string[] challenges)
        {
            foreach(var domain in domains)
            {
                var zone = await dnsimple!.GetZone(domain);

                foreach(var challenge in challenges)
                {
                    await zone.AddRecord(RecordType.TXT, acmeChallengeDnsName, challenge, TimeSpan.FromSeconds(1));
                }
            }
        }

        async Task CleanupDnsChallenges(string[] domains)
        {
            foreach (var domain in domains)
            {
                var zone = await dnsimple!.GetZone(domain);

                var records = (await zone!.GetRecords()).Where(r => r.Type == RecordType.TXT.Type && r.Name == acmeChallengeDnsName).ToArray();

                foreach(var record in records)
                {
                    await record.Delete();
                }
            }
        }
    }
}