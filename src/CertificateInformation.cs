namespace Conesoft.LetsEncrypt
{
    public class CertificateInformation
    {
        public string CountryName { get; set; } = "";
        public string State { get; set; } = "";
        public string Locality { get; set; } = "";
        public string Organization { get; set; } = "";
        public string OrganizationUnit { get; set; } = "";
    }
}