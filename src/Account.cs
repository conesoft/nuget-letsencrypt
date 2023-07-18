using Certes;
using Conesoft.Files;
using System.Threading.Tasks;

namespace Conesoft.LetsEncrypt
{
    public class Account
    {
        public IKey Key { get; }

        internal Account(IKey key)
        {
            Key = key;
        }

        public Task SaveIfNewTo(File file) => file.WriteText(Key.ToPem());

        public static async Task<Account?> LoadIfExistsFrom (File file) => file.Exists ? new Account(KeyFactory.FromPem(await file.ReadText())) : null;
    }
}
