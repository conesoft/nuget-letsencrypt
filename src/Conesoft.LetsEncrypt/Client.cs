using Certes;
using Certes.Acme;
using Conesoft.DNSimple;
using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace Conesoft.LetsEncrypt
{
    public class Client
    {
        const string acmeChallengeDnsName = "_acme-challenge";

        readonly AcmeContext acme;
        readonly DNSimple.Account dnsimple;
        readonly Account account;

        public Account Account => account;

        private Client(AcmeContext acme, DNSimple.Account dnsimple, Account account)
        {
            this.acme = acme;
            this.dnsimple = dnsimple;
            this.account = account;
        }

        public static async Task<Client> Login(string mail, Func<HttpClient> httpClientGenerator, string dnsimpleToken, Account? account = null, bool production = true)
        {
            var acmeHttpClient = new AcmeHttpClient(GetServer(production), httpClientGenerator());

            AcmeContext acme;

            if (account == null)
            {
                acme = new AcmeContext(GetServer(production), null, acmeHttpClient);
                await acme.NewAccount(mail, true);

                account = new Account(acme.AccountKey);
            }
            else
            {
                acme = new AcmeContext(GetServer(production), account.Key, acmeHttpClient);
            }

            var client = new DNSimple.Client(httpClientGenerator());

            client.UseToken(dnsimpleToken);

            var dnsimple = await client.GetAccount(mail);

            return new Client(acme, dnsimple, account);
        }

        public async Task<byte[]> CreateWildcardCertificateFor(string[] domains, string certificatePassword, CertificateInformation information)
        {
            var order = await acme.NewOrder(domains.SelectMany(domain => new[] { domain, $"*.{domain}" }).ToArray());

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

        private async Task AddDnsChallenges(string[] domains, string[] challenges)
        {
            foreach (var domain in domains)
            {
                var zone = await dnsimple.GetZone(domain);

                foreach (var challenge in challenges)
                {
                    await zone.AddRecord(RecordType.TXT, acmeChallengeDnsName, challenge, TimeSpan.FromSeconds(1));
                }
            }
        }

        private async Task CleanupDnsChallenges(string[] domains)
        {
            foreach (var domain in domains)
            {
                var zone = await dnsimple.GetZone(domain);

                var records = (await zone.GetRecords()).Where(r => r.Type == RecordType.TXT.Type && r.Name == acmeChallengeDnsName).ToArray();

                foreach (var record in records)
                {
                    await record.Delete();
                }
            }
        }

        private static Uri GetServer(bool production) => production ? WellKnownServers.LetsEncryptV2 : WellKnownServers.LetsEncryptStagingV2;
    }
}