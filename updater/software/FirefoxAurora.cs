/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Developer Edition (i.e. aurora channel)
    /// </summary>
    public class FirefoxAurora : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxAurora class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox Aurora
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "124.0b2";

        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxAurora(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = knownChecksums32Bit()[langCode];
            checksum64Bit = knownChecksums64Bit()[langCode];
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/124.0b2/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "0859a15caa5bbf7c51eb8c65752c5b3ddaba6cf08ce1cb81f458f22bba723066bc11a7aad5c005c6325fe7d95a3a8ac78671cb15578ab93c1da0ce581f23f6e1" },
                { "af", "0c0b827b264747d25ccf761244cbf4b7fc8034656e0548dd37a09608b459ebc2bb5e04ba2b8799e57883cb72a398c66759017fc91af0eaac2825e6afa753a1a1" },
                { "an", "9c2701aaf6a3bd29ae6447a629ba69c14d7af99857de619bf70bc2db3632fb842c6d6bfcb65e88064fc42eb1f12c447e2c03a5b369e5e03073f514717d1676c9" },
                { "ar", "8979bb88db65ab202e0da9c004a27ec1f858fd14f51ae70728186be6bb36b439e1531849858b44cd28dbc7606102e950568ae4fe48facafaf78a5dbdfe340fd6" },
                { "ast", "adc6d5ef28c9823047459b8a28a9b9e353aefb205c35c3b2b3862d6562bff27bd7ba6c17a4e1e41d31ba8733d313f1f8a3d439c25f5d335635424047151cab8a" },
                { "az", "68fe7b0199d188ccaa25d55acb5d135851d7d4c45e91e92718ff0089de1a7822137266d243be92a7f5b16566ad98affb13ba558b8ff5133190dc75c4c7f65464" },
                { "be", "f9eb8b4a07e2cacf6ebc29c7a10dc4ab52b46e888189db84569a8c613a0eec11464a7e8aa7eb9894f2d1c0f3398247938ac8ece2938fc2b56624ef73d506ba43" },
                { "bg", "ad5f622b53100e62154c2b1e1fd1b8198b1a78708702439ac91d6fe5e5e61f1bc9a84bdc608f216f8ab8d10d11eb6e292e8440dfb8606b7267184d70187d943d" },
                { "bn", "ed36eedb167638f8e8a792737afb467540c8f7b5f30aa7ec812c1210048a40f7853ed6e90c72d6f338ceb92112fcc544393cdfce67bdfe59d4f7f2068ee2cbd6" },
                { "br", "8b78fd13184e2fa0417d108ebd082f2eff7896aa5e5aecab27f05fb68b836594fbf4d64d1d92092e2621db58039421b833761fc1223f69ae99223c2cfcdc3c10" },
                { "bs", "fd6a375e00941c1082fdb1e4a5ba784abd7c26b91dd1be3536d4e49cbc241d223f36fd82ebf743feb38d0f565fc88a371e0a42cad7d63bbac437c05767e245ff" },
                { "ca", "d74e3e86b54c508649acff0faf84de6baef16d98282d53bb7bea07c053822580f28b094b249bf5ea3eb27fc6a79368bdf254a8e6fe64ece57c633185a87b014c" },
                { "cak", "00d1d5bc4ed38cf7355816ff3dc3e5a904da0f7b0e1102039da050f458afdffab12063acffa02550124ebf64c0606f42178a56eb3673a35231d54525d56bcb3c" },
                { "cs", "5aa83f2d6fb46c6a15ce83f273bbcc5217a2e92679403f5f6458c57986d5228e81c923169a28e0ca4d118e2617e5dc71da192b3d40af7a15e0187f0e05ff9014" },
                { "cy", "1ee25ca18c74254b398f0a791cf4aa9d1b68b47367e2030f7a6e7562adfb4f927f4c8d33da354f86aa84c34a9b9e9ca53f053503c825b6a26848c961099b854f" },
                { "da", "212c835e8b4680b199ba17fbbee64ddef455472496d204e332bd4689d51cd9f6bd875bc92bf65a32e006f47463cd8f2cce8ad07db50f796f16522d01e50c875c" },
                { "de", "670c72002015f89154f5c88ea8be312b984b50305044a8a07b530b9cc8f766062ca89c8d0342e7cd17869001dac695af5a279b5b0ce2b08e7ad1d3cff796b1c4" },
                { "dsb", "45cf42b1cac055e0b60dc9141635ef3996dc61d935a0477b76cb407c5853c20f3d59610677a3451560bc786f3101d89f97f274640b763c2760682fdd901590d6" },
                { "el", "bf335259a70b7ec2ade24a3b6d6389851c0857a2ef0a39dfda537a422ac7cc1b597292690ec2139a65ca8fca3dcd39a8a107948ec5c697282274bd763370030a" },
                { "en-CA", "3121d6e40e6d09bd267e3f794c33684c1b58b57bb2923bea7fc91c272d003c1131a5aab71a61cb87a3c4f5564cb68c7e4e3e76f35eb709ed300aab9849eb5e2d" },
                { "en-GB", "493c1026f79ea26e916498b957864d56b2493049f7f6eb2834b16370d972c625998094605d5dde4bcbfd87a46dd259daeb15658e3b14780af5f73abb7d031b1e" },
                { "en-US", "aafdfa143172528664b23d9d27a3cfb79be696421529f9af8a608ed2592f82321e55c00322cefbd00dd2719bbb73514959ae73f7ec0798c566a88104798fde5f" },
                { "eo", "1640562931a2d8e0b7353480ff65b17aaf183b09b62393b7b2f47ac2d7202da97b5b78d46fea783e43a2e31feb94f5b2427148b01cded08af72e66c93b771f1c" },
                { "es-AR", "d15a0d2d2c65e18c5d8c6553e83ab57c43b57e5b2b94949531e681ccef90b9f0cc76c1dc2b18a854f09c284367fc5e75005900cf6c84956e4f5e6509a9e50b1d" },
                { "es-CL", "5002b81abd6253d3d120383827d9b1a4fcbf06fd5837398ce1f1525c798dcb31eee13860a62a91f0a938de2432d75dc35fd6285b9e7a9a202650f19233ea9c16" },
                { "es-ES", "180f1c80297cd6d56d5b76bed587e040a10218b6d9bb8a6fbe1f35a16e2b580723b9194d7865930c429cfcb361cbd532e1c9fc55e6b85c9a83589932cecc945e" },
                { "es-MX", "466e23e4776e696bc2b68a10c2765a4e6ef744e96ab04251cc6f035f8fc51d8e740b1e4080e4dadb1b5c0ff3153a92f302a2cd8dad157863a156eda431cf515b" },
                { "et", "c4b3f434d74278d6411ee2c2475574546ca293e087b09f7c996c645f77b8da4dfe4b8810ccb188d04b440aec5cdee58ba3d8003a9828640693fdfd7cf8da9673" },
                { "eu", "b587a91fe1562cadd078e02179819826634f3051c71f265062d9cdfb4c1915c4ff13e24c700e530eba1544aaa91806d8ac303ba21eeba3419fc677b283626d08" },
                { "fa", "e8abc161f9b00b456f4af606a872d2dc2f2c71dfbfdb6fde5f669e3808578e097746baa4db00fb0701a00af19582120bfdedf737820a29a5ce841f65124122c4" },
                { "ff", "c728e9a1a70e59c52aa4c544211afae2344d90fb7ce8330adac58e0930ebb81a26a49d45e6921c7e448fe8c9c6b23c644a18de26087b46c933787892020a70f3" },
                { "fi", "a959b4e57d788fe8f12db3e1ae9287da06f3ceb391e5fdc115f92835a4ab390cced267f03ed1d52477ad16bb15fcee50bc9822b0732349a8997cb73812d2c38d" },
                { "fr", "3e984bd760b5d9607094c80cb8492ccd236417691b5c4eecfbd502412be741304f1449981d3526239e1b90603b6c56f89e5e35dfa5ebcafb82e7cd2657f6c1cd" },
                { "fur", "73322264ac2b9d328f200d8fcede5139e73aa679a2e99cf347969232bb1cbbf160fbd46e958e30c07ae389bb25543516f339ac327d6cdbb3da0d3e5e47738c7b" },
                { "fy-NL", "f63397100594103cc7a24eab221d1bc8187d3c0eae870ceb2f54877db52052e7577b318cd97accbd813f757d9ece3870e02c3be10648f0a95b0b1d43995f14b9" },
                { "ga-IE", "e6b55e5bc16084f09e50c723b89837c71cbddc89233c7148907813013848d82641c501d3240601aebc9278014bf10e43f1fd6c3c307084790dea65d9dc4d9db0" },
                { "gd", "8fd6103b4e4195534492bc6838e559bb4a69dac23f7cb8318c63733354e6d5e541674197f182bdde202528227fd13ae783e421dc04eec105cde75ccf0e58b44c" },
                { "gl", "3f419093ee7a1279b8e49602a57089b38d19ac97676b536cc840f0f123805e2ac0dd4bc02d238fdb680a90a882c08758c25357047b5d3420065375abda9193b5" },
                { "gn", "4b7faf48f9345e4ce2fbcbe0f43b5e284c2ca076bec9648f091633486884b0ab2bdf8fdacb2eda920c70e6d9704cd1077829d2359dcffe5b96691c3b81540f9b" },
                { "gu-IN", "2d0a512696f5cb910c7fc33b2b936be9f5ff64ecccd21ac2774fd68f16d6f6357db32aef42ba6a86fe35db5d3c9fd83983d1e10ec4ca2cb247d57efa2c7f6139" },
                { "he", "be9e46ce3b7b6f779f7650839564fbe4671820e85e74e84758aa8b06d8cc30f812ee6dffdd50b63a58c98681171fdac5554f7c44da4b2a7229b67ae8257abd1e" },
                { "hi-IN", "75b9eb371de5ff6a85813825c6bcba9eb21f6aeb47fc50f982cd7f70b8296beccdd0dec7686787cbd16bded34c0818abb3122e45f92513a4bae053eeff1ac81e" },
                { "hr", "34d84d2046fe706413d74cdb7a6301e7e6a8da41eba523d445520877981303be5c629e068161bcadd04a85c3de9d7acafa98c75036a4c75714f931252c0ef35a" },
                { "hsb", "2f84a9cad82e86e62a7b964fcf82ef913f176789b2ed4d5d132752331e69e37f615504e996c9e5e2cfbedf9778b9e92621ce2eb3d69495c3850e2152f417ef9c" },
                { "hu", "0587afec3b55502ddaa85ed7cc7e6c39bd879b273aaee63562c112d08fde750a6cd8bc1e3ac6a14bc3ff0d8f514fcff77c7f3ff00220151885260e8e1cd4f87d" },
                { "hy-AM", "c0f1f80b700b7b55e847c683059ef140756758ce852bcadb8ba8322255363b1e45b287038eb10792ccd429a0cbf0ee808ddc9af5124e7e1eea92ed964d0e7e1c" },
                { "ia", "c3509a2d6eea2d4351baf6e38767fbd4960ad384b7a84c02a5b140a61a6d9a6f06d1617cd8a2ef5ebb899092fbbf8ca19f51f678750c06ea6d2738cf852b7f29" },
                { "id", "916741f0b12c2d9d13df1dc74c96166ac0c3972594660bc48a2438de1bf363f01454d1338a32e3707f99db9fee03cd20bc56919e8b5a5cb074acd3ba216a25c0" },
                { "is", "750fc781898ad8ead5563e38e8a1ef9d75143961ffaafdcb1cdda8a9a6e3d9c74ff4ff012a9f708005192eba182c30864c60aea49eae48dc641527fd970cfe17" },
                { "it", "c34f00bbc5f23c21fa6f35a52b0fd2815c85b4f4a89e3be06e55d3075c9b529f4a7c09af1dd7bd6c0b958b3436e0da361f878838617c505e8bf24c6563972923" },
                { "ja", "691ce02f65392a14f29848cd812e7d614877c8a24c53055019f20f46dc9334efe1ff3f0ab0aa6cf6fe75113f35ca5d5304c7da25ccc8730b4e2afe440a9598f0" },
                { "ka", "e3b9689f56d95b12b14c2034605f851f1bdc7b955491376ef3683949558fae8a2d2ac8891c292331621a4df405f9eb4981f90c11b06c648d91f4a3e75ee85a93" },
                { "kab", "b30f98ce0c07220034432473eb0e1d494cf08b0b820fee1bc3176a76b27d03943cd9166d97b7c77e46a0376b63e898b1049792ccb8445ad03047d0ff4561b62f" },
                { "kk", "8bf3b4c6c7c9ab46b0991f333e4e3b083e5d5efa6456a4ca64bc53357d14f618edfe3f1fb42985a06860b916c3f481d2f9f8e29d775bd2cf596314e2dcbdf9b3" },
                { "km", "f36f15f197406a2c1e58c79d7800d7d925aac9d8df9a185cfaaabcf432afd276bed2ccfa3ee6fd09a0bd73ef5d1fd30a6bb00b97ebf209c8f041bd776773314d" },
                { "kn", "98c171b7b3856020ebf2da0f2d09edc5db8f3454be197e94142f0cbcb7e2c749e356ea775be526c72943440091afde0d02a4913a37f3e8cbdaf54602c2e4d8ac" },
                { "ko", "96d9253ad8768e1337e62ccbb18e595b1ea4b1004f0f3a11b6cba875d20971045bef64c5a3307875f54dfa390974ff56394b88a55031ca6e7a94b03e05e88e93" },
                { "lij", "08b8333c5d1bd4decfbf8ba7475e54816e7820a6d7ae7b00b6392387888f4e1736adb30ce656fc5741ab8e7eaee2a9ddb9ee18977b01405a67ece703cbf0ba12" },
                { "lt", "e61471d5b16400550239cfa7bd883bdd400afd4a0b0dfa833a84b508f7ada2b70a8f561e99015f86756a4035cf6f39c27ce36e2205d4cf774dede3a23661d852" },
                { "lv", "afe3eb0cf5bae438ab6b779e4a809cc13186a38935a066786d41e35164ceb86a90a30d2830268857632cc169cd2a049d5f2406553a66ec1a48ac4b9bed51acb4" },
                { "mk", "509d6de4d8db30e1bf1e55129b5d460934e6e939cc6ee573e8a367dc7210c0aa22980cd9f75e30d059db8012dc79b839be6a77ed85d69e97cdf7fd7c5795f5ab" },
                { "mr", "0f60e017bae49698f4eea7b511d38713c79757b3bd65280955e258521ac12c35ffc553c672d472c04a1b90689d2e0691a5dd419011621ee3ba4d64c21b9cb312" },
                { "ms", "5be39b62f748270e8ed6985af2258abcf336ff0698f5e11cc6b8593838fbd8b68d7d7fd0d06a4d5e688223e6782ee2a482ff28b7fbca428417d355a5399072f9" },
                { "my", "72a950d6ad36552c901a5b8bbcdfd8fa413d9b83e3291322f3204b45075dcea8d4030fc1f91820e497a7a7708754b436879a4e62013c8e40103548b13cab2047" },
                { "nb-NO", "d9585d62c9141121e7c0855983f3c058e76604d1a687b3f083f29f2671981b536bec2408a59d875be627c81a691e4a95c5e5ad65af85e0f75c6e919fccfceac7" },
                { "ne-NP", "0a192b01dd7028123a9af14bed71b6c9d0eba5ffe213e31f99df487e7879523a0926c9775750ebaeac1291ee80e51fc4b44f7c4906052562152c65f2af73ccd0" },
                { "nl", "32aada2a6b7f45816156e43a68871ecb39d76b88a23cfd7bfcefbecce2f91ae61e3a8ecb2e567dffe70eabc52cb81efd70a0c64eb465bcc574be1037a8720774" },
                { "nn-NO", "34074400550c00c25cf3f2e03d3f0f10782ace403b5a41bfe4db48e09357961ed08bc400bd2e78a7f3314c04a5a05d0d6d29e56ea2af7642c87634b780204cb3" },
                { "oc", "cfda74ec69d641a9f70d9db0649073f13068de85d416490d733ba7a5940dadb82dee26a973013ae686d4ff09d048b2c689f6481c83e62383be0b8ed10cd28e74" },
                { "pa-IN", "d269ba46c8d1e3bbe4e08734afb4dfdb633b3526ea0001bc7b803071e8b53954394479a77a7efeed747d0646c33a1020845ae09bdede6a43ced86a17fc6afe6e" },
                { "pl", "9e204119f72bb97f3ddd213ed494a5775f4445cc16ed3ad669a05a1bfc8f6ebc67774ad65b0df38f6f64cd291e159a0f7c1d56b41fb54e3f9b4f888047694839" },
                { "pt-BR", "625cb58ec12b0dbc27e1c38c11651693dbe568d0a5ae4ce1dc34bcec1b7f9c21cfb554c3e398be64b6a683805e21b0b59fc06b6b752b13a64bba30131a8a1c72" },
                { "pt-PT", "99d4e7ff8446a3fafae2e8088e2853f2ef9c3494c1cae19b5202e83744575a0220291a38f10899343a0b4924a05c3d83a08ff247e15e89ab2f21aec13d53644b" },
                { "rm", "39cbf7a94eb723dea8d9ce233c83c37e367f8e402922acab6b5ef2072db309ce469cbf16dbbbcf0f81029da73ec631660d9520121b23d8aa8b4a5f4456e4354e" },
                { "ro", "155e821e138571a3e05467b98c2941dde6ad27a3af36658165e62c7b9569a5072a5fa5c5ccf12286bcf32a8e809d96f4a7fe6fa5ddd93a999f624e28fec5a005" },
                { "ru", "d58719733d198ff868de86b552d77b4644c2cd5ed352441bce2f3cef684c9742884b6fac0ec5f2368f01a18192653cb22046d611ba60152152b3bf85fdea838c" },
                { "sat", "1fa49ea5b366bbb777e57968ec95d9320d87a8b62a462743ae5b90bcda41d55992f192dc9184cafa4050265df2ea3ea127338d6d80875dd04141f5a28e9c6499" },
                { "sc", "6608f2eba807f15545c9bedf6d798a3cc56c32967f85ce47e07d119fe317aa15df310051b8622b04316549da2b497cf52c4e4bd88825c864444dc9f29bcd1921" },
                { "sco", "1f5eeaef449b8e2cfd248e23d2e201a3d12b2af579942b99cc1bb785569a339fc57efa7a2e5333ad1e483ae9d1019af41a72084e789f94ab21c81b95870d991a" },
                { "si", "6809955ad3a613eba362843cde7844fd9411f8c8d665a3fb564db79765667ef9f62c459098dc9337cec1e710894d8e9ad6bcc83114d7f449a3e1f662d853a901" },
                { "sk", "2725ad27c803f12c16797e365eac17f9dd11ec5ec291b5de78a20779d71353c2c60fc362702f634dc13476e7dd067b75fdc327f8bbefcc19b56023447272ef8c" },
                { "sl", "ac2099a2b7e64b550961069e1b494e1c037dd9effc076b2d879e7b34a3763dd3fc99a24aeb388d718d9d4f053899226b0076f88ffbabbe7be7fa59378285ceec" },
                { "son", "bf17f432cc3e017b348f0fbc38242cfd1c331277e2d1fa962ea5d8e59c79e0dcad136bd6b26ecdaee6f58e25f3a013d34c8a897c26d58cc06e15d1ca7329fdc0" },
                { "sq", "d611fe71d0514876b70804f760f229469bc8625cec6c4b11edc51700500b08d922e0907b983a457a2f929ebf04b09300b10562d78398e9d77fc32683d5c2cc5b" },
                { "sr", "093a8bfdd2febb7531cc3abc737aa98656e05c81970c79bf87d75ed9b813de84ef0ce0e20f9e5a22fa981b97ac6e113b7a5d0303668c263786421f9ab362d74e" },
                { "sv-SE", "8ff50d228c98c9b8853dc0a9761ccfd96f560183e9b2cfb8ca78bb289199079744dd0a90d59445407bf9c3599e0791866f69ee24c1b96fc1ec604bf724e7b644" },
                { "szl", "16d5a6e22e19edc0cb16f381f72fd92824f6b0846a5e3fdf70c706cb82114a525381db7283e7f387d0aabff9fce0d85e4377a56d5e680dc1d47ba841b2723500" },
                { "ta", "22124e558ae36c0f18ffbf30c7ea0e4bc1da2d2c7d128f3c10d9f923cf2091fcbfa9b508414f6df34603531033251a271f915aa627fdc1aabd7a71e67e70a2f8" },
                { "te", "a4d5d631d8e32548dceee0d3f65f208c552f1b76fbb2a105f365cf09719d237617aa7069f80dbf0cf262ca6a8230415fdd519a4414c03623caef4ace4914e200" },
                { "tg", "7bcf443bd337d353ccc396256e709c21763814fb8ad4367aeea04dbd8b5e959f7e48a84c20e687b727cb0caad93f8d06f5aec31a1929d7b1ffdbe1b295f22d0e" },
                { "th", "cec694c100e04c77f8192ec73c3f8b02a2fabf161f3dd30ecc483ec1e3efac1140cfc75d4b8ef1be80a2b5d87367e6704a4f2676908fd942606836360356db13" },
                { "tl", "22b5b0c9a51c012adff1240c365c40db4687fd6c589c2da9b53cf628ec63fc1cd614ed517cec708723994deb580b68a422ed1fdccd6e77564608ae46999dea4b" },
                { "tr", "83d0906b54f3ac4f886b90f85615a3c349a087d71017dee348522e87d376a7eedc020d90ca0942b2d18f24508f52874675b6ed17b558698396ba2849dd23a206" },
                { "trs", "2f0939610fefbf9809f2b6908c25445f61409c997c98f17be9e23158c033212806af6bfa8a2b6710675f22c4d1b292b8f499f5c800ce7a8566ddb09609ec62d9" },
                { "uk", "3426a4ed9af92e19e4847537ab22ac94e4790f38306394efa1b08a905b0bd52f7a5000edfb2efa871d550c8e54fa0aa8f4a13f0d32b9f66cfafecd81e1ed8b3c" },
                { "ur", "94391a867434e846a6497b84cd3647b4b8879530940a6b62efbbc17ba9863eb1f14ddc8f0d0566656f7732c6cd5285fa031fbff7ea01f888ad19e8dc24213305" },
                { "uz", "fda7cc4c50ef1769da010adb7dee40c545b57bb660962eb42117027c15108066153a8facbaab0b20c3610582914a6ce6c4e823f04f87a40ff2b507fb62c0362d" },
                { "vi", "c3d530db13ecec5cb50264a9ad8ace6e4269922d270ac407f2b7b570312ab8f655b6c279b854f3e1e7fe24832785f14fab1bc2fcf37e431015c78195cab82804" },
                { "xh", "9353dba1b704aa7dee42c8931c0a336e644c5980973b0b3940ca8393e10b22f70c1ef604d80ef6594ce0529dadea3b5bca609f1c030c4dc838147aadaddb276c" },
                { "zh-CN", "e0d2d9096ae73a6f5aaf76b38aa635fc61a412b5069c7f46c903ec061610a2970ba9eb1031219af9b07215da46be3c5cc2c671189722c8a413926a6d085bdbb3" },
                { "zh-TW", "be468fd12615aa03fc71f36ed36ba3e23fdee1a83007af6e648bdf381a9766b0e1ba48f237c34d34e73a14978b4b7d63373553ee4789b39d982994a3c1695364" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/124.0b2/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "5062a1a3d782d3642b9323a42a30849a71640adf1d66526fcd81da62d6afe4e10f3b8a43bc11424dc8ac1b09f69832adb317548391d7ca8d49aa8312449158a5" },
                { "af", "52f956f63130f566e77b0799d8425fcccae365c407361bfef77c16e585e5abccd7ef2be4d1411ea0ad995a8c0edd4930e397d745f2ba6bd3e90fdc36be4c27b1" },
                { "an", "b21aa6681c1252557af884acdb23d56863bc0188ffe75d7b8be97bbc5dd1eed5ffd9107cd0a71da18a7cb23914d3a6022b755a1a6a057579c00b752d5368a364" },
                { "ar", "e6e52aee9477b928f8cf14b18b34b7b3f9d97a0dc0e614450f8bc041355fd01dfd5527b6568113534da46620679524b03e6321fbe3f072a2c17e0a21bec2e848" },
                { "ast", "bb9ef9e990219a90d9aed4e362b59fab09c505fc2444113813372e362103acb53445bd1376af1c9fbfbb994fca2c33b4dfc769793583a8b007ba5d4ac7bc5c8b" },
                { "az", "daac7decf39314e245e1420649302bb681b21e956922898bd5b195f4b76215d085e7ff6b2112aa13b766ba204da3cba5f72fae92d2dc7560eeb99060c702d1b2" },
                { "be", "874b431fc9b2c7aa180b117f35ea135ed99c4fa495d7727f84925bd7dff561c7363cb67fb95f35645485edf7b21f6d70bc885a1a92ca0c1edf4b13a2b6bf56fe" },
                { "bg", "b5410a81bb7327e44f5bd1edae0ff9d7a888136ff45c3d08b22c040745dfe138b612f1b2393f3f1134b0d638135accdb4dfcdf54c956a5a2b098744c8376bc00" },
                { "bn", "e891604d0228b6ce659538b231cf93187a4d57d6162a83669958d28c902c3a753419c32d5f02e99a00e1eadab724c80d287c3ed223ce760cf38ad41ac18f0c94" },
                { "br", "5fd98a699c8530bc42e246bd0d7c11c60ab92f1d7d5a5b2aa1877b7b25fb3777b5112b588f473a6812c6e40506cfce9e183ddc4dc7e9570a4c34d3a85d25b62d" },
                { "bs", "8abce191875e4c55273e0b39b79a8a21ea2183f4e3b0e914c990c81d556eb3a8f8bb0bee81fe5188122f54de7ae93baf4e942c71d06bfb52bc52a124dd70ddbb" },
                { "ca", "626b72ff330daf5f867ed601e5e9c0778a4eb5d7114f8bec3b9a6c46ec122f77c504149b11826e4b935909648d5dbd91a9132eb34cc208dd2be04fa969e78f9c" },
                { "cak", "f6d7d449a17b9a6fa90097f4d1cd6cf51e350c3682180f37e1dd5f08f539e675c09f9d07edfc0775181991ab2fb9c74115a255c5e3258ef0412d924f69f5b667" },
                { "cs", "41d375d986a260d2874a9e0a33aa3671cdd5edb3ed4ebb464c7c45928a8d7ba666e00d31ee7ed635ef9deab8a3a4caa75171ebbfcaa33826df86e6005ffbc01b" },
                { "cy", "2468343af4bdbc85533b104e4430c9b4644b56adcfb6cbcbdac41865a7fc76763c475291acb4dd6b0dd0123d7ff2e791181f038818321ed0734bbb810c5d34a4" },
                { "da", "dcd88c6669b5f11997d139d8b7faf993c3542b56e7b8ec718e0fb46c1353c35591ab52271d79319bbc19771f873bc36d44de71ec707d2a097d621d96e77e9505" },
                { "de", "6b38496493605f0e7673adcb8b8ba06dc3ce25c2832887be8459825eadeb450a6cf341a2b5a45c250bf9a5b4c7ed78d78824b274a4e26ec37206f8edbf45206b" },
                { "dsb", "9b4588ca2466f0608f0682ded2533c207c9d87d2538389fd4546e28e4d0fdf7756565b07355780b6a7e595c1348d17133fb4a838822beb30f18b04cca9a4b5b8" },
                { "el", "b332f2395414c0700c2cadec0da3ff68d7eb1d017eae0b6bc7286d983116446c94ac2a6b52eb1c8d2e585db3660d1d3fe2baaa13adf3dc0a82333de2572821b7" },
                { "en-CA", "ec09660e1c21b60941882d1717db797e405f603dd30ca066166b8185a08e18c9d3c3a5f4c1aa60af9ed8e811fc6d8631ea46e5fe8b7625c7cdceb43edf0249e3" },
                { "en-GB", "083a99caff0ca9010aae2d68f49464873d13c5b64a81f592c76603d4a8f7f59d1a8381b5ec13f5ea3458bf3236c5ee4a14a2fab7cc251dec9f7a3bfc7fb59ead" },
                { "en-US", "7976bb9d86a65b1ef68fa9d0394c285b07fd0070ff893e378c785313523f61e77b6fb7b49235066b65a89521483143d2cc5a4484cbec509e0bb03a23da4ea612" },
                { "eo", "7ac686c7fbe6828786136b88d124e5d7ad6e496d527a5407016eb7f2b81a436488f77b729cbf39b55a62308c8d9d9405d66aed9ecc97178ebdea8310bd9b8210" },
                { "es-AR", "d1d452ef9254c230c3d5937b25f18ebb01b5ac15aef2ae54ab4a00db016b2b03077c7474ecf68c8da0e1fe09e425293c8077b1c8ff2e4c6d63fec071607cabb4" },
                { "es-CL", "7f8db77189a4e60fb6dcba5358f02ec1f622496b0a209683c265768b98bae12de9b4595f9b4390cc7845b0e4238b5eb819025fb28ee3a96ee103ecf21f0df600" },
                { "es-ES", "e66e8f10f829b640e79f83f1f0f0c45da7708bac0a53575b26777578b7016ab94c16d41f172421593de5a57a97126caf777e5d030d923d9f239027fb909aa21f" },
                { "es-MX", "0351a7e9a0a6b1af51a0013a66033b74d3a7d46daed72fbed529b73d04087a844633b86840b8a5dcca8dcdb00eaa1f3dca0105bb7330b320b5924d22e64f0bc0" },
                { "et", "e6712a32cddafff7a3c24a49cc96d60ec806dd5d4273bb75d7c86617a081bf3f40cecdd941b9f02288adbceda0e3e2e2f939349ac906bbead4aaa5345b28d2c4" },
                { "eu", "57f80de0338f17b4de27003b186db56447b6386bad504b3a2315bf54cef3aa267450f01ea85a4f5fdd1c5b053170d1827f881a0824d0acd509daa34c6c4edbd8" },
                { "fa", "68f2d3b8e3d670d45bf3ea3bca53d93d0613db17bf45aaf882da4b47c74b3b976450913103b02973cffd21c2f0248bb689f8cb61432879c7579416f8f1db6d39" },
                { "ff", "1cf8a122059d21f18a2b0343e886ee329f7a4f66df8e428eed3cd6cb263c22ddb5b01fd441a5fb1bcedff21dd915696cdc0135ce10c5f9da5d44a21483c3980c" },
                { "fi", "7234e96c45a2c7ccd2c3cb47b42a4268aac2188f13ee13e55f2c1711132c4fd47937c09d18be7413419544d490a9066b88a4d8707c1f0c9fec428c9a1160cf99" },
                { "fr", "72a1bbb716eb0ae08f080beb6cbae18189753b3887c36084e525cff293fd6983d647679f67968301c03e0e9633fc6e293eb2bea134a63c5f000a162158247977" },
                { "fur", "a479d14b4565f583b81ba0a4ca709c21086880364e54de758756cd1fc7370f05777d5b8e24acaf494010a77ca141deea880a93d231c955b36fa7980631b9be80" },
                { "fy-NL", "4240da919544c41d19851f85e44c743d1ea3c07806ff66ab944274bece7e2b07bff19a1344b34a0205ccb85ff3de9011407afb777006c95ebb770d91b8bc1fe1" },
                { "ga-IE", "81b66abe63a6f0b2d75ebf493abe1899d5374c0c80801a7ec00932a46f195be72b6d0de7e6c2297e31a42dd66f2a46a75efcda715423b8b1bea173bbf2b8963a" },
                { "gd", "d9e080f79da5026771ef41c154b58d9f4ed806d7379bb9333cc2c8bbf51b21a4adf7fe73dfebf3761fe4fea4122555a843cfd8251e12b97c0d792de04a09b3b0" },
                { "gl", "00fd2a17a8e8d5fb2c9b67adedc9cb1a7877766ec16504a5f353b065fe3fbdc567ee85d2db70215105da13ff459c7f3e14fc0510895119f6f7e4dace73f7f03c" },
                { "gn", "27a85aa499c5dc602ce4bc9e7fa5af064773a9a72eb68ec736327fe41fdd42e730bfdb940c0f48ab21c804dd06d72028bfb058fd90a4c4a8d9f7fed8ed65dc53" },
                { "gu-IN", "0372aec6c5351d1497cafda76a2994275006ff39e30b3659913ec161af0be9e3dc24e176f1f47f97645ad4e352672cc58857ebf3b39f470f288fb11c6c21b26c" },
                { "he", "636a9e194d26f74e1455a4df723c3ee899209fc7e364cb9dce73239032381bb79a0d873056eefbbc179c0647a9801c97e0937aa4954424c7d5f7d6798e3c16b4" },
                { "hi-IN", "931c17b19f3afb7b2d08f58a66240b3b6f5fdf1ff7501c2ecd2664d6fb9bfc0de7c1138ba6b6389a5159ff346cf2c2c6e06381ef375eeaefe7c17cbcec3adfe3" },
                { "hr", "679a15500d5193242a2e512a23456929621045af2eff8e72a9e7c6404d4beeb35b12bb25580e83f2199135077a51fea383fe4361f075fd1f617072323b0aea7e" },
                { "hsb", "a5c6970445ec8333b981509f4f78dbef0b8fb6290678ecc6f148cb6b6b8821f4b4bcca61a1d5dab5468f98325c8837c7aaee07873d1fe7208ab9bb73ac1508fb" },
                { "hu", "b8997351e924402a83445a736b5d85f30e4408cb775425841195cf74bdcc960c944fe923bb9d709967967712a046167baee63bdba875b9baf87b36b045bb89ac" },
                { "hy-AM", "46a9c7f20ace5bc0719cca7107b9f8d8f66bfda8b4f5293923c7377dd6ec0be21dbc5c929de3504be284430c8746ba424a9bd59aeb058cb5b975552f2119061e" },
                { "ia", "cfc4e4e8b824c2e1a76f343f787acfa7612594b54013840300800e351365afa84174395bffea95849749826c2e4197868b4f39436ccd5fd182a5714cb6ea39dc" },
                { "id", "f752faa3448a51277b456878e4f61445710a960b7b4c763514cdb06321b038aae33d69b1a46b3d7d3ff02a22204a5d27d6be82baf10f541358b553eee7891cfc" },
                { "is", "d691d4a222d2046ed1fceb644067f20f633bdd2de3a3a564f492f2c33b24e8412f1f832c07a1b78aaa6907c46948a63e964be4e988091065d80843e5c5ef3e39" },
                { "it", "9e361c19b2aa32702f2325452d29cd9c174b6b93ebadd3b2a53c3aaca087f19542515eb16b8d7f39eea448023b324d52d3eea0c2aeff9861774e5bd88e114f27" },
                { "ja", "b92cb43a66166075b9c8c07f7cbcabb806ae69d476a6453a9573a6cf73cadd5b91ffeb0e7e8e8aaa11cbc5406d79c9eb1f82ca954654a77277e7541c131d375b" },
                { "ka", "6bc3c709898ceaf7f3fdae0328506db731ae3d8d039b58d99a0bc1b83dc0bd11c5c3cd31250c99c4d300483f67037d4b753eeb739dfd76fa4b7d8f5333a43891" },
                { "kab", "7a03ea998031ea48ed7ef11838657c69fc684003b82515532d8cdd2f616b5b0aec82e1358c48a810d5d767e18fd76267f3add038d036a7b22021e939cc4008ed" },
                { "kk", "1d2625a11d8126a5c4c59b5319990635b18e907f271d6cbe1f6fab6e32047baa0ee1efb3f2ca078b34e2cfec379f87777b0803bcf16743667664f4bdb07d1ce5" },
                { "km", "02e7c5bf02f04a7e1ff498b994fdcd025e2c9d8a0f3983230518d79fd37f195e279f0f7c6d45b2fc51aa2ec2440fafd0e7b12bbf80d514e6f9a118e44221f65c" },
                { "kn", "9fe8d2ab889065d2ebdb07b9709b68d174bb1887f008f2fb5ac80da2de545faf299f694a918c64d35c255ea3d4392ecc922328ec4a50dcd9b8fa481c9624aef6" },
                { "ko", "84ea5c4b20a13119d6d1fa242f68063f5f7ec851ed7bd29997f3903918d035a0e38101ac1e6fc15b92f0adbf361ec6b966ce45d44c6267b00670acd7f524690d" },
                { "lij", "81761e4d0f3116a6134b00906f1a6866f7607f50b7a0057736cee0a5fb245d2da6ba83ce68e060674fd5d5cba21ad5d43bde64dc888ecb3cd31167310df8d51b" },
                { "lt", "62945d540c09a053e3eed70db1c151d22d40bf08d5636f273cd92c6b547b883367c1506c55447404c25e63dbace5e54d131f0577016bcc6a6f321531f2666f8c" },
                { "lv", "8725775ed84a9611c3daee79698693b7784855a0971969b291b330aadeb44028f19ed21c61d112ec9e761b7a3ddff97bab2faf87eba1cceabac9e9ff47115739" },
                { "mk", "43317b6bfb73db3e26c58b6860bd0840b8dae90a031a1718389524625d5e90617fc29e23e2c40b31defc790de413e6d477f95c86d565a658ce4a9468e25c50ce" },
                { "mr", "ccf8ef7de2bee67263f4a51e5ea48662b6c42c69ee48e97d77a1310d15ddec25657a6843b0eb911de9a6e91b4f9d0a2bfe01be588e5c543f02000fc3ad6d16cd" },
                { "ms", "025ae59cb4edf97662d30fde24b992cca1b6120ab863ce8aa834568069fda88a68bc6da3132aec2a3e488c97d01032d26e0e1dc81931e41fe3eb761ce9e60624" },
                { "my", "31082784c36ca33f159b24ea08837c573abfd6263728ef662fd682c1829bcbad795d2d96264234554c8485d98c2aa5ad1dbb9b15d8ee8ebad119b44f877b5e45" },
                { "nb-NO", "fe5f3547e9e5bc771080e42a208c921fa9a27f9a4af88dee4c31c4b43f8066c34bb322e4c3d0227abe71fe939ef4c9548f22a1332609d19491372d27054c5bc5" },
                { "ne-NP", "d1d3541421546082be9ea3a245055ec9355c06a79ce7fc89768bf910c27132184606b78e2d3f7c2904db7560a800239e80c72a4f7f95537a63d503de9d82230d" },
                { "nl", "c5de5140cc8ec36c5199b074545186173b249f6ac41dd3b9cd69559e7f4ddd6924c7e64535d7fe2dba0b46024df0fbce1372856a6da614185e3768b852bad56b" },
                { "nn-NO", "e02eccd39d5e127abb8224966a87836fdb48ac095b455ea4084cb56839c19e92bbbe369b152ee566c25019d7670d37aa5bed6a32cb9789524cf5a5490f1e6ee3" },
                { "oc", "4b6f8e549177a5ca131d50ba1d084921c4275c558fd722d21394d298d9947c70571ff71f41af7352c0490b747562a5ebd9c8e15f837f84f2fec70238d621a19e" },
                { "pa-IN", "64cff6050011b5719b880edb8d60bf2072488bf67599cb14f5b232249fa20bbda187b9ccd9327bcc49f1f5fb29ac305ede6e5b12887eca4603ce3bfc4b010486" },
                { "pl", "3d6a61e33da7882807798ec87ab24ba18c14c57c9594740547e3951bb27c23b5a2ff040beb460db3c14f1e8baabcd6b2d1ea6cbd808153fe05081f209cca9a0e" },
                { "pt-BR", "a536b89eb574c0d705b8aad34203daf3deeccc5853ad15e1da386b81971a711cb8f2d5ce9badb01165f9ec1236af832941fbe88fb893662f43c8969c35c3faac" },
                { "pt-PT", "26ee1b1fefcbdbbf820ee340da6ddbc553f5e81d69823c05c1d4b19743fbd8ef2ecba2537fecb7ea8c1323d055874b29a282080740e8f361057ee97792359ef5" },
                { "rm", "3a75803e451dcc8f91904ded9b6c539befe25da1142551ea025eff73ab3f23f94ba351ab9ee3e19bbc20499b6a63afc737845afdca4e7cdabdc3cd0dfebfd41d" },
                { "ro", "f65d5a93a11b8a7ea5d6dfdfaf154dd186c7066d65ff816d28443a36b745ab205a48b21f156d79024a9e1cc7027017816d34b1907cb18d706fc7cbe129fe49ed" },
                { "ru", "4b495d17411c3c8bf349957946512d7bef6d52acca526db98a9ed6bd607658849da934f2665bccf2fb876e4fce81b7012360794b8bd5ea73ed20a1d90da9b195" },
                { "sat", "9ed731fd26b5b84627442a39cad7fdc9a63f8cbe9d4b305de78d8f5618a4eaab354610b29d5a9c16252c232c4c6c3ae3a7893a81cd747d7d0b2ddc98a558e0e9" },
                { "sc", "14ac493b79a81706a438aaaecd3c005a3d36c03c821c3cae0f055b12d50408a12cb96a4fdb8efdbc1e681cb21435c349d8e6d1dad318c86aea0a3d1e25bd0edf" },
                { "sco", "fe92d79a78344374899a9216ee01c60d24b6859c79e19782d4c665affb45376cb453110f5ee61f1c31c11d1c9e039d150e0527852461ccea4e8017d7799007db" },
                { "si", "eaa084bf94e7a546c9155e273d9452e145260af98e62389d919a0c32babab6a00b1865e2755268dcf612f451493effe26622712eaf1f11db0f98a92133ecbd5a" },
                { "sk", "114259a52dae32232342b9f79f8b744326d4d9f3e47fe0aef9eaacad6aab69a3a648162debb674c5b6ab259197216724e3a2653b1878f075b47ef70f5806d005" },
                { "sl", "bf20b1e619ce504b5e1353004a5600ab539ca2b67220c4158e7a9b224a7efe4998fffe69e6b488afe9d84ad3cf2692a02179725dc0d35513ca3b4a0c3dbbbca2" },
                { "son", "5a2abfb877b96d9fcf38b05c4b38a6b13dc6c9e12fc60e2d0ce18fefaa79a18d73e254cc6db634f61c992c065988d411e9f7f6817fc10aedba71fb14b4c73667" },
                { "sq", "f3ee3be794baebe60662b31404d2cbb7df08268edeb3d65708e4483ec808372df873c68f245f76420ce202dd9e8e459e6fd41258f44b986a1198bb41ed808a47" },
                { "sr", "57fd2a634adecf83351c5beee8b8bc8ba6044f81ba5d6bc30f6fef3faec61e0b7d5304b589ab1160ea0ff8a9ad40dfe3293fbd2b762e7898d6a017eab9c5c8c5" },
                { "sv-SE", "dc2eadf0ed14d195a7e94264f9bbbab984c1776bf817c2111a29713c89eeb8c6878957143d8e499e646a5cb0f82bd8a417d8a10f4cb30def5b10bd6f09a7a890" },
                { "szl", "31b04d8c8346c42f041deaf5c9267efde9f26a00d2061d19355bc7776580498a74ad4381fcf9d617cb41cbc4d4c0702215830d2adc34d71fa447884d91936ebf" },
                { "ta", "f4bb11183547a5bc4c11bfb632e9c293244584886daadf8ff07536977c06f6ca1666cb1889aee95278fb9723d0148e1046e08882f91a6e464c400967b2236bba" },
                { "te", "9aa952f35751f7154a13a320e6f91f39ba0df91936d587909499667156bed3578c4fb0a9d34a3822ce8217394701f0f1ecbaa59d282701eb5d1a7529dae5a186" },
                { "tg", "412f5398a3cf001ba0d1b280756ea5cc805458167acb3d944fe9ca24db71f7e1aed2e809dfab3bb7d32eeb4e2e0b3ccb5b6d67be509e13e66daeb171eb435008" },
                { "th", "607cdea41d34d7f8239e27fd0b727b057481d24300297882e44121b4f7b04c5d1bf3eafc0574b9ff41949bc722f300be480b6675bac295464b066bce82ef6cbd" },
                { "tl", "1721ad3f622d03d217837955e077a9f13c5d58983416b86b99e621592b0e95b86786c56db4f4a1afca34a5ef182ad6b7f2d642616a8ded1a717e8ce67a7a4433" },
                { "tr", "fca033a49411147941359a08a6be1bd2b05e05d12117a194c9d36dcd29dbae2695c8e73670afde9d6e80bfe6274403f0d50cf9038ef2113c3a120da2671434e7" },
                { "trs", "da6c283be29429eae944591ec7e13c981e7c8c056f21a7a1cd1ec74e74c9cdc3b69e71a7c73bf73f53ee20559cc370baf16d2ec97b4e6736afcd1e7d0130c313" },
                { "uk", "2fa000d55259723600a7c7a89461d710212b1aaa19e9cee12b8ab7345ce1f652ab5589299ef982e49e1e3cc6697a8d0f51e6cf04bbb78114fd27ec4e8867a8f0" },
                { "ur", "95c1f4a680ee978d86f4352df9382f8ff35a6ea1d83ff4ec3eb63a90eb4ff85346740cb6b6b2c2ae7c69af009b3787d71f0d5b56441ebc56ecffc315bdc13f4a" },
                { "uz", "9953e0b4ad930765c9596c496f0b8700f57ba81e295fa922a6dec9d978d2f109463e6561bffda5236dac8c2d228f16f3e50d80d2e42c1f2257731c5e4856b44a" },
                { "vi", "eb672c44879931969d8258b61fc9d43ff45c0bde3c677cf736ba824e742416a7380cf8bc75b3b6fd0617a83c8b4e1346fac9b47f65e14d4d6627f4da5c0a153b" },
                { "xh", "5017e9ab46b5544fa88a980d4ae2f12dd96d735dd9fc0d6934afb8e565b2b8759ae43c4fb2f17d88f5c07a1077fb6574fc3847737369aa96c28c78a64739c252" },
                { "zh-CN", "f6ad3b0281453e733be42cf336e4e7181ad6adb5a96413bb8267600a832ff27a19d8bd673d2eb47ba35caccf25b0d6e843ed663e7e24dc06aae98f6dc00b458e" },
                { "zh-TW", "9aeea4e580cf8dc3c6b6ad48926cd1421ff300b638899e58d9a0b2d2a8fb90a786d4a88d94291813570312d70b98c82adb63a87b92d30261c8f35035974c93a0" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            return knownChecksums32Bit().Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public static string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                return null;
            }

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            var versions = new List<QuartetAurora>();
            var regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
            MatchCollection matches = regEx.Matches(htmlContent);
            foreach (Match match in matches)
            {
                if (match.Success)
                {
                    versions.Add(new QuartetAurora(match.Groups[1].Value));
                }
            } // foreach
            versions.Sort();
            if (versions.Count > 0)
            {
                return versions[versions.Count - 1].full();
            }
            else
                return null;
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                var client = HttpClientProvider.Provide();
                try
                {
                    var task = client.GetStringAsync(url);
                    task.Wait();
                    sha512SumsContent = task.Result;
                    if (newerVersion == currentVersion)
                    {
                        checksumsText = sha512SumsContent;
                    }
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer"
                        + " version of Firefox Developer Edition (" + languageCode + "): " + ex.Message);
                    return null;
                }
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64 == null || cs32 == null)
                {
                    fillChecksumDictionaries();
                }
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                var reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value[..128]);
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private static void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value[..128]);
                    }
                }
            }
        }

        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // fallback to known information
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
