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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "131.0b8";

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
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "0ca1e063f3b6ad1f6108977bfc65148ee317e2cce7b8c1122793f0eeb1be84daed87dd112ad32e9f66df88a6d51de949850cdbf75842e6af75e59e15648e65cf" },
                { "af", "f3139c2472142eefd78f4b1e9a89af8db75ddcc4531e878268917d3b3cfa18db8f8ef91cfd66251edbd17346477bf4bb1e71c86398287cd13f2ff3653f369c24" },
                { "an", "99f3471cb61d3cab8949254fbeafa3f447601dc6bef096abfccbec70ed6aa4e65a3c4c73a0c23d161256b81bff8bf6c688b30b29416db0d8c49303ec1890f829" },
                { "ar", "e8cba3349fcd85f7b7ab14c09799d45367f0f5b7765a0609332fe5d8875caab4ab9a2ddfb5648195ebf194440a0f348bd88b0ba4c50ec4ae837533e844e98d03" },
                { "ast", "ddefc3de5ffb93efd93b5fb746b9aedc32a755ff3b92083c4e4376ae9ea7ffa15459b503e408fdb012358091cd07e2e4463a1646d58e5df3fcd798ba097c62e6" },
                { "az", "fb1ec97e397b6024c18c9710252b3cd5feaff8a9516f424d573c45be942b261dd2a51bde1a0b4c5a9c5a3381dc3fad06827f163f145f7675facd9e29899f4ae0" },
                { "be", "28963633cb00a6e775937ac54c1d0aeb4cc9c3a94bc1e02d203fcd5116656cd29384e8df72788df5cbc35e36bd7d197158ec2832d161f55ac48ea9ea37745eb9" },
                { "bg", "a164c76525cb1cda8e331f3b70a27e1acd26614b08f89173d3fb5373f0db9441e3f217822b1db4d41445998d0d1b2a765c3d569f5ff087808ad8762fc992c8a6" },
                { "bn", "33b3aacff622bd172aff9c2624fb868b6b8edd95be2ac9aeba02491e51c89f1cde80919e3790cce6c0ae8a56fa9a948d2d0870c0801309c59df3d1fb4fee3df6" },
                { "br", "09b4b13e2a765eba0f11831f96b75dc3665c9b0a04bed33032422c73828e1f836086c82ff251324921ae3e0964bb7fa3b1f923601a6a93eba9fd3df661eee200" },
                { "bs", "0a97f87cd3dcc0a8037a81d34a7a99853c79ff07eda2f86069e9f624afa5a4e9b7926a40b346cef0c5a9794a2310c3a308b87cfe99e1a04892ffe54e375661fe" },
                { "ca", "2968084b548de90a1dca1bc9e06dd417a26215a4c0407fa8d4a8b3d05773ca8910f0560c1e6132a7bc387e5a0652b6ed7c64877b09eb6ff70140dddca8f984eb" },
                { "cak", "8605db0641ad83f4d787ff259623de03132159b86d667f79b0c8b3912e81eb09b1d67dc08a1e647e7b89abe8ea366315f665093c8c8df61a102ad551828d1b24" },
                { "cs", "443c253fa0b13b95a5f382587c5e31aa112a1dea327c570179560f3a1bda3c5fabee8806f6d594213d985a386086e53522667aa433f01b7237668f8d20259a56" },
                { "cy", "2f121205324157e87a4cbb1829aff4fd285b6c4d4ce312314af120cc0d756dad70d7e20b6f80ea26c8283c27757bbf6ad1b144be90fa6450cc36f2d7b796c173" },
                { "da", "1937e00db0a0743be3eab7df67b182c47e5373b83dbb5b9bf1594d4cd471995856cf2000376f2e64f51e44cac2cea173560d29d0c021125fbaef59342d68d035" },
                { "de", "5b5c11eed06c10a0c4ee57e1c8ad794cd62f9bc5e37298465919579ad3b83b4623548c02fd0ea7187c541ceb396d8f91400734e3a874b634de775e5fe946375c" },
                { "dsb", "774a6c71da39d4b73953759f5f2e1762436edfae954b5c9ac08e6491c86f0fb47ad45ba7d142d2ebbfe4cdb84d4556f219634d1168ba27f6567a094923ea94d5" },
                { "el", "abedca888f8b80de1a85df4cf71475de403cb3776f2843ea3f1d6bd893e921b10a4a01abe18c41f84e57dd06c0437148f12c1d26afce8b2b9093f9c9e461e323" },
                { "en-CA", "660023ba9ffaac7aeb4d296a1365eec01fa6a3187db404662f4a5deb947a25aef4cc227b764eed2d9b2aacc962dd9b78670d4ff600919c3afd6769b611e3cadd" },
                { "en-GB", "f12283918c0eeb5e43d23cc318fc8149b1a70aa49a48ee17222d955ebb33607d3fe3825c9ce34f42e43ef40bfd61ed7f5b96b45c0c0b76229573fcb086144797" },
                { "en-US", "97fe3724a7c8319c497759151f1d8dce28f4d213405e68624f34147ddad0e8424a40282a9e2e3d747f69b811754cd0c12884e83545c926b9de378eaeb2e6d735" },
                { "eo", "4d584a965a83965f0e65c57ba3a9253ec0cad0b6947e0ad105440337fe49df976b8cc70b6d401595faf39a36616e3a6360cfa77c59121dbf218cc8b376166aa1" },
                { "es-AR", "aa714c115a70111ccbc2ed9e8cdf77005786e6d313e4abcf237da0a132d37b40a75bd85c846be6502940acec5a1d9bb7fb64b2a538b0ebcf8e7f6aff50d9d135" },
                { "es-CL", "bcf731fe11734cf551c107d35f15c597273c3f0131acd78bd7f34599618e976ca5f43f3cd5934eda4f542e075961e8cf56794f52a56f23775963b67c3bddb5d0" },
                { "es-ES", "76da9b7a9150285456bed3518df6eee3b3dee001558f54342cd499f591f16bddd1d640633e0a106f367df914c4a36c2c677ce0f500eacab163b917c8cfb7a2ac" },
                { "es-MX", "95dc432fd05435a2ba1660ae9209fd5fa8005267da6bf31a3e0b726ab33a6edcf50bbfcf40da482b2471ea39e3d6a02605349a8d12875121ed1cc0df31a2a816" },
                { "et", "d937c9cc9f0ef33785f56e86c35a5f7dfd64e9343cc291f1e98211317d1a11e7525f29137bca579cd890d3e9d47d9d88658d12057ce280301d524387174e2ef0" },
                { "eu", "19d5c784f9448e78b2454125ba447b61836c648754ed559264838dd36e1c8bdb833fd6034e52376954d9b3ae96703e226970e21acea7ea265122a7bcb6da2296" },
                { "fa", "4fdf4ec856180796e7c4af9b43c5a426ebe9b15057ba117a0608c236f0fb0a4f1d68252cbd63fdf85b13e411d81ded79ce8d0989706c665a4099ea0ee9e70842" },
                { "ff", "a4451575a3fcbfd498bd4fd35784bb2af63b05749e79cc68a5144947b720bc6f5ee6ec95af061cabbcfe2bfa27b2aebc357e717104e8b262653ea30df7eb334e" },
                { "fi", "8ed9f88b2751592dbce570b4707c7ae90ae5a43bb607a56615444e18bd7eaedc3677b65f5b7c19158f8872ba21de917a8dff30bbc1ea13c93dd5d55e74cda385" },
                { "fr", "7e68a2535cca277c2252a68196f90e8c9777fd201875c402b209412d0007105067dadb80483554572ba2559cb6f8b2feee2693c26c1a2a214c6a8403c31c6fe1" },
                { "fur", "6a94a8df7e74bd1046e738328d9b242658c753c618de624008d5da8cb3dae01ae08903495971b11414b0f736586e37f096433f2c658d279ed3f49198de06b96d" },
                { "fy-NL", "361d2066ad8bbd4b17b3376c016a02a9fcc886b858bc6b67061122acca40acbeb330c543d9b78701421d9036cfb83b359dd69e7d2bfe0c11fee317a8c09f6947" },
                { "ga-IE", "a7644b0f6c28f1f50050dff7a570d14b9c7b770168e6e0dc4b007de3e03f33f265be763dfd5aede9db0ec0e287c11ab22c0714869fd9455829850b6f05ed1afc" },
                { "gd", "706d7b758cea9cb2a685f1332c294d0c64bfaabaabcec9fc2b3af543daac4c8e32d0accd0e25a1935bc25fb09c1407f9499cde972ba37f204057cc0ec6e74b6d" },
                { "gl", "ecc5b4ae3397f52fdfb56e7be620df8bcc95d08c1413b03955813474044866235c48a8eaa19f411f733686b40d759774508de5838764289e36cab86620588859" },
                { "gn", "0b42a3295d580ee900f8f056db28327d3474c2b696f78c538f2ca8365e7aa82f0e7762a0ca11b8297b7a48a39bcb63380d6e682b572373d3ba809b0a92918add" },
                { "gu-IN", "c9e5214412fc8c17e4d516f853c82025dafdc5c1731c6760a1ac5a06bd194d1345cc7cb4a431cc5acad6b0376283f104cddf461ede18c96f586f62685aa363a6" },
                { "he", "00853d4fec0cd620f8a66b1ac4133e5fc4cca31eae430a3c58c39628c7f9920f255addeed0c88bd1b92f16d549939e469822c34d7d47959b9ea2dde998199787" },
                { "hi-IN", "5d51aeb4585b437300014699c73c7b0ef4d47c4a76ee826fd31b9ee9ce330f2eaa1815bda51ebab87312d11f4b078f8dd5fed684760ae179fee8ae5ce1e8de35" },
                { "hr", "fe0836ae3704d90dd38575235a881d014e6e6ff385aeebfb6819766649198617d9410c83199694710ca415fa62a4147a9e7d963fbd011c35977a85f6bf75f182" },
                { "hsb", "e0c9cf0bb9a0dfc924750747c6accc64d2c1526c0a64c77a2d34ca8b88236b100c0b8ef413e2717164ee19d03083f4be0bf8b8611334fd9a2cc0ba5e9a7d69ab" },
                { "hu", "23c09fd6ae0c7bcccb73067fe81762b7b17ed64e358ea0d379da6fab12dba706e2d62ebc65df9bd41c4af9d55ce012ab70e10c36fc8a845ae4ba6ef31f8b3674" },
                { "hy-AM", "93b7bb60426b2b0786d583489c6b858398bca77797b695228a98dcaf7c64df7b21315ec4b47014b7332c05a2865a5338ca48ec9764f9fa62e3fbf3cf04a33e86" },
                { "ia", "30123f80aa54327c85aecc360bf15026ebfefae49b524a427a6c7c90b6109dd817756d0ff917fb7e83e8832e69242889f02ae8e88ca72c49dc067ea323a7d982" },
                { "id", "a051c86c0d7cbfbc035614cefbe4ae86025db1e6fbe54ed03aef323ebc43220ee436e7874489f31837d6b18c1b509de25a6944babef2494a3629a3dd58c9afd6" },
                { "is", "94ef19235fe88419c0092f9ea9e727112ffa4d0b512f3d6abaac8ea51c6c5c7d31dcd9824347f00b5e037eaf8b8ca4d83cb7173f03238107a2a71d81257456fa" },
                { "it", "f731b40e4e323f463bf88d6b4d7cacad42c53c30cd6b080ac4baf10c6972996684371b3ad4e8cc22a823492ee295d6eb7d20150f9ec861897c4c3c90e9067e73" },
                { "ja", "f736f3a7578b09d6ce45fbcaa2de90344b1d48e63e53eb2bc5b82c35b7dcabf5e6659d720f6667586a367c1e47785e34bc48b3b03f465b596f32908ae21d6bfb" },
                { "ka", "81cfbd8f0f5872c10f3b6b545d9366db3ca323ebd0124e0587ba30ffd3af48b1cc67b0f6f317302d09f3dffd4e5ad266fdda96f9d0eee239e15c2cf7db44bad5" },
                { "kab", "ae4a508f9b547d2dd61e0f20df73f1df564fc6ee00aa5c2708874b45745b4f31abda44a741e27ad9efcacef483f9f3187cabfcfce770e18170d3d776dd434fdf" },
                { "kk", "8da2eb9e4d642287c04879384b6d666ab67dd80bec6f8feb5767ef93183e18f5f73b4ce62e758ae092f94ecd5f9b84ab8c89bab5c88cfe3b96f71ca3307f6ca8" },
                { "km", "92e97f2a6b0ca1649240f8cf7cf4ffe6236b2db630479c701f1e8adc7ce298f2d7e851c8d97cb4c95534e98105f54a644bb4882629f74e5367c9c2a3fd1232cd" },
                { "kn", "7c78c534d126c378bbbfbc3d4a941d2e34b3c3af6c28e636ef595a846cfb1d303ce7ee7163b7ca7519697cf135799e8ca0a8f77e4716200e901d80f87329c42b" },
                { "ko", "92b0057e2f2646f22e4d442f0080c1aa7ffa7fa5449ce9c7c1b98af9e5ae1a0c85b2fd19380cb25b7b23f0ec1089b4903ac45ff9a3325ef00bc6d1b60d22d7fb" },
                { "lij", "378ef5dd999fd4852767722e473e7122c063eb713a909d552c56b2837c4459a4413f9d09adfe1bd385b2567a17b595acb33551de551da6f5b0dec15dfa279b8f" },
                { "lt", "a11561f9135cf4c10aa1d713ac91e8bcd3f3f34b8436177db7b6dd9c9223a76601f7897aeac78729f98b99ef6c4838002004966a1af67488ce287683c6901017" },
                { "lv", "c3c7bc2e0d54dc93f2020286fedd220f05982f5ad662153ef83117633e142e61a0c9a533586fffc839a08caffb9ff2a27e39a99f56c0f5530708110792bdc4ff" },
                { "mk", "0c9fe0c60c81b87f368a998566af009ce7514d1df3e2a641038235a374fa0990bced425a240aa813a2707282f0ac6f31b2dc15a5744e3c3edd582ea0647543bd" },
                { "mr", "f1c2a21544433cf3db53fa3beea0f188989fc3886a7962f24e264c3823eaa93d89540878e8ea59ace218b1336c3a781395de9f7ad20a42d3e91f5b3c82c0e1f6" },
                { "ms", "1497622890ae6580e4ba012ae298de4e7359d3a39bb98dc00b946c89dd535ad0298b2faaaa1308d73be6fd04d182587b1feb11fc4852d6df32cf36f9be26eda6" },
                { "my", "839f8183ceb564b758bbd13daf5d2bba78b14cbb9c282bc4c7c06802cbeb9d5c953135dae5e24b1d6a3e2cba23993d6ec66b615691f2e08764f493a62b2b09e1" },
                { "nb-NO", "1aa645109b615ff0d2a6593d37e932790c11b9976e2f23c5082edcef6dd2221370738ce93ca443e776b33b6bf83d1a5b5568d926b2893d4f7855b967f73dc47b" },
                { "ne-NP", "2418dc69927f09a21de6acd0b3aa96c04d3b4143326a88b81707b689747a39345b38eca8ca90c49d716990f77a2b11d3e045af350fcd82e29b876d2d8b6cb7bc" },
                { "nl", "21b3e330d2498158509902b7ebe0a3f4185994ea506e7d7b69b3737a791f3d9d5408ae96ddf7f3aaaf5a3d80089b95b426980b027d492ce5f186f9e12e0458c2" },
                { "nn-NO", "bffa8149b690e406021675e8b305458cf32463f25d02992cdf04668611ed98468a77ac5c2d06d84ab39dd9994242d94e2ecc78028acbf26fea3231a04333a04a" },
                { "oc", "f5d46899961e5237ab27815bf1578298362f3ae1ca04f408be554cf292a9a802f36ab17f213ce50006c64f0f14c87fb28873624e7a81510876d085dcfca4d2d3" },
                { "pa-IN", "1283497c598fb06539b0572ee5943cf06599210f1cc6408ea4631d6a150ce4c0aa4e27f64da2310955646a10bd190ca2174e58115f9854a01456ca10773e6382" },
                { "pl", "e4bec0d90f00e8217f699fa01556024110101ace9fd230e05ab3b5f46b93e72f4ebc88c0b277c43d45919e13ffcc4980fabe372708d5e3039f71b72b8f600ade" },
                { "pt-BR", "210a5f941c0caee9d64f3cfe0068e2743a35bd9b202c2b92e7eaad9cbd13981c33b5614dabdd5cd0f2bcd91d8c1eed5bf387a148e11b377fa57f245fdf80e8e3" },
                { "pt-PT", "e6ae0924fb83f808f216319486d248ffdebb1c42233bd5fef34b48b855246e85a3d9d756d501130db36f7d701fbc13401a41443c0bcbaf6350a76e67ed19c358" },
                { "rm", "ad142293e41a00ca5fbfebece8d8d223e54d762bf82bc129b0e9f208b90605a6b196b8beb52108b8c130015dc75f325e95d7506bcfca55073d9096ef90f2ea76" },
                { "ro", "1a696f11b34ed5056601b88db2420d1e992f956fea9659332042a5a127799ce5c9f8f3b0b006e4f5587ebea0b3e0a997cbd4e799c88afe4c961339522ee2c566" },
                { "ru", "80627473af1670f309ac4a47983f32201805cabbc0a39023da7efe55ab71120f06fbb1ed396b8bc80ee0c9cdd79a95c3ca4ce4823c79f2e502225be33767fac9" },
                { "sat", "8ea6aa3705309e02f3d07b9cc2142fd8e1fe08b6afecde129e10aa53be0128155c3856841dcee6342ea45a46c53dd35672d5c6bacce763b3f3c6a12b61a90ec5" },
                { "sc", "a683c8222452ce1c497d50259c9f2d05a5ff317f0fe68ead6e55d5926e71e1b1e86c5b6536ecf0192bdb25dd59d11b9909438f0957c0012c158e9b069afb2edf" },
                { "sco", "cefbe04e192da0a82fdcdaebf4570ac528ce41a83d104a6c47680eb49de42b3b13ed52d135e9d12eae89bd88a0f168fbc7f36acefb05e35c86404a6437b85a42" },
                { "si", "3b0a1afa818f6f99a84f70e9d801e1927754f8242de57596d44954eb81f69ef2df743683e3efc5ef2156ad9b7416ed66622c435b0763a55dda843378c5ec977b" },
                { "sk", "3958f9e2d09e2b614150010d433c27156a5966974725cfe4e58a00c1d5b772c973adaa05fa54541b9fb704f98bc8f4ebfaa9c1918ef58be17ed4433a8a05bc50" },
                { "skr", "da6968087068b64efa43fd918b681305b772cdcfef9411367c6d2ab0427c4b7afa155b0dbff448ce8b91a61ad0432fdbb6719621bd97947e09c5d8306b566d10" },
                { "sl", "00aa1a23d61f22a6f27b2425ef695c18a9368ddf579ec8950d3e9a5463411522c6e0cf84591c58f69dd300188b6e7fdd7b7c3a7865c3d2c11ffe6c692c45fb1d" },
                { "son", "a32db6ffc35b5606d657d31895f845757cbf42430df247e54e1af99499013144f8eded5bdc2e4f50589e5e0ddbe9a433c36a49ddd845d0f64a4801da101249dd" },
                { "sq", "269edad7c82205640dc4cd2ed2eb2175757b3cb163fcce869f400fb135a989f913fd0184cb7af81051264b3aeebb1b4b32a7f5b51c6d942c47cee90dcb24d598" },
                { "sr", "6340ec0732b94ef5cc71d3dc384b3b67d86c1c36b638fb5dd62f329f1c05c480f3f7a969533030c41bc0f91d48ed760418fe1b40bc9b97f9d728eedd3fd38527" },
                { "sv-SE", "f3ae32af92ba59aa5c3f44a137969972f5896283987279be745ab2442e1af767fae39e3db888230638a76c3c5b6066ad251fb323b407891ab2ac385faa8745ac" },
                { "szl", "bbf5da47a064835b019b22c5bcccee266dc02189a76eafa5a6aa9296dc34d5eefdade1cdc620037560158f174cfcd8357c1fca6325470076ed6743687bb2d379" },
                { "ta", "7bc24c36574e52a1afe5417c993ba01eb84b6968ee16f556e2c70eb09da63ff6204eaa109b55fe3454e41ebc8df8cd279f600061c49f5f8709db54224766a3b0" },
                { "te", "996af3105e89f145acff7f4e1d27a80fb8e41b58c1508133b032c4b09476060071f81b7919650a3f0abe1d5957d813c6a821a39dfb30efde4c6fd7e111749255" },
                { "tg", "41f06480b1404919fa66c8579bfa81ef4808b61144af0dbb8b655072797c22c91acba90708cc6ea9ae6e1d0bc6a45383ec50c0117661568cb745ae1582cb687a" },
                { "th", "379918d60e8efa5cd387845e38afcd3c0b1bec34700738e865d608d9ba602ff43517da30b7f61d09aed89043d2ff48c9fb9138b6abf9f4633e6e9d33e298cd02" },
                { "tl", "6ea58244f500e5f48c647592205a89d88cf87fedbb78aeb95d0be8931499f04bc3f3f5c4afdede6c43d19212f3db8a95744170241e49e0fc4f28f3cde7b5c97e" },
                { "tr", "c58a1a633f6a5a8d68fc81fd103f82106d85b5955094e189c29b95cc6f9b32bf8eea7b77f6791f200451ecc59e9aee177b48f46229b33119aa04897c0baa0326" },
                { "trs", "fff20be8d823e51a49f129a679aaffe682c0454536f1f14b957c88b898cde5434d81818e7514daa2e222bab48587a87f17b0347818b05245b87ccee51ef29542" },
                { "uk", "779b37372d29beb36bdf30986b67c7c348545103b446f48e5f2214b7a99099a38f1ce7664d5c1c8c98493f37c67ee8d5e305c0f264b7e6e1d8ceed7639639bb7" },
                { "ur", "150bf9069b30a82f128f1a5cec81f64c1d9b29f3fdfd9d707c8f534246c52739c13f539fd9445711d54a546461404456ff8c4ddef8aa6415e2b5cb19d54635bd" },
                { "uz", "91ff749e9b33eec076801f344526e0fecb6d7ad624ad79ccc0ca8c8634e0c8690a2953c35df5490de20b45198ad2c5f74bff31d4c35e67578080a902f0447350" },
                { "vi", "43a8bda92ded3f17febbdf4c593fc1ef974acd9dd14cf1b7e5d92fad5301487f5fcb34964fd4e6de8c3405c67f98bb1903ea994fa2707ac64cae943f2a3cb685" },
                { "xh", "5ec174cd8a5b99ec827066ec49a6adb44a16bee6490a6df6948680f55d01e09035753c2c8447c134620ea4c6a2563f44924e22045f7c98cf65ab4de612e17b01" },
                { "zh-CN", "34f9f232835f8d067eb78a1c9cbe0936eb9f9f4f149a94165614ac22d9b78deb09a7b7615110c701a4db66bc39118a422193b7b052a5337f1484125ccbeca0a5" },
                { "zh-TW", "cc7f19561e94df6edf0e4e7d0b2169ee5c140aa6216243152faeefa82a023e80435c9cf1be9986db613daef3879b9f8e5f89894fdec6233eb2b4f47b822bdfcf" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f3311dc84febd9cd04b024f2e6b7c5b64f30cccb8b6203da09848988a40227ad45d70fe98f8bbb7b8897f817b2b4eadb16b16d34b3267a0dd4c5004cdabf0e1a" },
                { "af", "7f9918ef6394127649d3f2a8ff8643607715f7e38e8be4d3c04ae543376c8639176c9a73cc94d04905e4423eec62cc051ed8865de940eea3f3dc773d0d0c1e53" },
                { "an", "759c3c59f736b033d982f133084ba53351f5a5420032b0d4e3c837f543ad7dfb0192a5f79373b4fd7d58e2352f44d6a9aec3adce2af10fef160973ceee8f6aaf" },
                { "ar", "1b9c9b2a8b1986c7fb0e7c84558bbb5b41c2ea7af3af1d713bed4485c2881d6e5837671925d20f1567d4ef4f00204a97d95c3bc8de88a6ab5273642fdd161bc2" },
                { "ast", "97e03f7cb4e91d434140b59df0a3450d06ef594674b4f5da249b7bea844312e639c2198df8ae4f75079d39960886843c07ca9343a6ba86e54612036f89c2a58b" },
                { "az", "e938328c1fdcf829b2c8b0c45e24d6dee7ee21b3b139121b801a439bfb184fcb713557e49566dd831783584fc6f1fc7a3fc5f210c761e47d015c0e4cc49cb09e" },
                { "be", "af23d59a99d8fef1be867712a4d5337bd5fe7103f13a58443cb7c7940c1e20fc834b5c443851664401a0dd79aabc0c270a8cf711c24c0037588453ae191dca6d" },
                { "bg", "1605d659406638a145fd1117de015953cdd9d976c6b6c61beba0b8111f23d2e52470fe67653eecbdc9ad10d5084e0ebcfb45b0c18ce2c3f45b771faeb87589f0" },
                { "bn", "b4c3dbbaab50e60045f8c43ac1f187b869f3c09c68a9d8e6a8364f0393f1e1ac3736adedf14f1fb4dbdb83dd75fd3eb9a17693f7eaa5d132121d2877a8715af8" },
                { "br", "14f9a21b0f5421d5b55161209bd241ae294d880becd9fd697be0e2d230d60b47bcc580c1cf361774bf8c2139c62a3df26c31fe1ddb02d6c8c58c263a24b3071b" },
                { "bs", "05434a1b4b3e46ae84041e24a0eba478e0cb902ef8766bd185286e06c3a5953011e9afc1d64546214cc1576f0934db7a435a6f18459cb83a8f893daf96c53525" },
                { "ca", "410044e41e56fa7c17e9052a24957fe33476d0397dac7bc35750f60e1df37bd65b8d02a027f65f1a31f40da607e3c928d9fc76343a05264ae4c4338b67a2b0cf" },
                { "cak", "0918643b79fdf49252019fb1cd353cfec748861afac8d5f9022db0ddb5ba8071b741780df8a08ea6808e2dc10ba331d6a9534a80fff4a93a6fc677d52d3238f3" },
                { "cs", "07f59f441334bca1044bbbc8031b8a6f797e46c8fd022b2e9b664f53a59ee019a8069a0b8d6f423f3670bfde482620aa60579c19087d857bd576d1f5ec4e4c89" },
                { "cy", "bac6ca355a5ee822c9ab41c8f14fb186aef3f9508a06490fab6717a4b8b4c238ab4e7fb007a62a6333cd9760a71b739026ebcfead6f1302e24162b748a54aa9f" },
                { "da", "d88bec03775bb03acde47d316479f9554478627da890a3ff9d963f80d42689ddc7b305382e3ab458fd92b1d2789b6bfc7d3d0639bf6f83e94edc9dd3e2bee3d5" },
                { "de", "b127f6ce9ed47df661850bd0839456e4991d41387d09f91b6786e8488519828e1dfd6952f075168fb7b20deceedf1f505f05fa928db42303df09d608bb2db2c4" },
                { "dsb", "39a1e8a3eba7aa3d6c9e09dab6be56de0644e7ba453978fdc2f88051e3182b687a74f4bb276bb4f3a32bd6f58ee67aa89199debbbd2b84cb3261f0d20e2c94fa" },
                { "el", "1dcb7d174c19c8c6112c6c59094bafe95ca474b87abee8429ddc1715893602fd5ece514d1fac7dd74e7e7f141a5a8ffd0e09737afec6059b2ee5329d2efa0d86" },
                { "en-CA", "eb68f1b3749d28846d9c89413c070be99584c0d0fa01458f4e0689be0ef21eeb7a100b9ada2067df2bfecff21b01784c73810a738889702764198a453529c75d" },
                { "en-GB", "0f00d7fdf3175104aeb6b880fc67d8e2feb14c73845ddcea9671ddc11901d9a859eb4643834c5f0c06a3932e4bc072765147dd14a3d2389a42910e31a6e0e4ad" },
                { "en-US", "d78e4b228cb14f91b8a5c694cf8bed7d7935a93df59c649ce15737e5d5c98071f5cdf771c834d4a6ca2cd15acebff94d18ae0a9c866f5af8bd95882530b4dda0" },
                { "eo", "4dba608845de40becb568a58f2e5a65d0d805747c33f36f86a015cf395bd7e5c295043f796853a59c2357ee38b8370912d0c885a4c279aa955e835318d711f2f" },
                { "es-AR", "6b63df68449795e11f5404d67d5b7fbc5ceb94895086c54267df57ea3717decee38096dcf80b06899b993a54b94fcbb9c070e6aae70dc74bdf50519da96b89d3" },
                { "es-CL", "eff19b84e9ec0ea897f7e97434b2eb8b320a1588ce72b422e83106d721464d99df322303719930f840feafc51284f04d75793d1b59fb58c8ef750219a3b07a26" },
                { "es-ES", "667d255674dec4c63719f5c741656c8ed4f281c51d3b6567823f7d660352aeb34d058dd1bbfcfa07458a9247246e12b8f92601124843c8edbb1941f86db5c045" },
                { "es-MX", "fc596ed67f0047c145cb5fa30a218962ee52c164c854049252d4ba290878f588fed3edb4339b41ec03ee16ef2c24831da55e6284a1ba36a6601b9ce3dc774571" },
                { "et", "27a227fd754363dca6ebc5a7dd7697de38af1bdb38bfd7163221f66b59e39d64f88db7931e623b2cf4cbe94d87fb31bfe3a89214931624ac42c3e4b64e79e02f" },
                { "eu", "388de68b484e5e8dd769bd6aecdcb2bab7a62895102bfb85981fe2c90cf8408061415a98ed07e355cf59ac245aefcb36b02f089842ba4c7221bcd4fe981b7d46" },
                { "fa", "3d015ec53be28d3800123c2547afe49d1c470c67b7feda5f5c4a4059f2882d71ca23e381f1ecf712c01f59dd597a7332efb15141aada970fa83f7830b9ab8be5" },
                { "ff", "bee91a44928451a47210bed3f3342f764a12f2dd76ad66c88004672e7e5d972cf678d431887ddfc67ad96b959e4afc5cf2d97f08411a63f85dc8f8f92ac0ad76" },
                { "fi", "b149acf25635d39dd505a09b7e56c408834a1f6e0848306de028626674a8a4007b996da7ac2c5d1d1ccfea4e2a5a9e261400f62f2ccb644468c86b90908cc491" },
                { "fr", "ae38d1b22025af1bef9eb895921a32dfe8115d96d63dbdc72c3a4b795c86399b5f2cdd005c8273e5e0e3b2a0c9deeb2865a206985b96eb9778632694d8b1ed62" },
                { "fur", "69ebd6e8dd0fbee1c42fba81608a568ccb14c682b96d4f03b284cb5a2ed453c7d393007752c5e0bba516e603be21ccd1fede70e9f8194c4954eded37405f455c" },
                { "fy-NL", "bef47cc3a5bbc8909efac1e22e7890c7d701a3a6b4a9d9f9f0313a2b18329dbcbf04bf34f84e18a3a09262c1dc63fccf60620fe67c14de8a0fe1fcf72ada708d" },
                { "ga-IE", "ef7167b2901b89fef33f79b2eb153731a79c82b1996057089d2b7181a197c82343cfb63e42a5958992540e45daccaa0ead5fc0b87a18f61baae7fafdd5f65be6" },
                { "gd", "4538573646666ca0777d4b6dc5c7ba18015db471ed13f43f73e31ab4a6fe43904d517c615266e5cea9a423d44379d571c63126fc1e3cf38e0e83a899cc4f2ecb" },
                { "gl", "31d276c6cd4f20a93c4e35b0f5716f058c2fc019e49d4f9d3c1bdf57d7fdb26969b0f445d8013b412b5ccc9a457c4cbcb61ad2cc2ca7344a6aecd9a77ca56144" },
                { "gn", "3220140726b941df2e45cd7e075ce7b0f902c3be37eb44b1ecfb30c6fa2ca849224d9f2194bf5c5c3524be972f6410fc170f8b8fbbda5687f6ce8721347933ab" },
                { "gu-IN", "b67c81d1242b17d814bf32b9be10858c0d356f28d05ac78f0f5c212898b0e9d1d40e023783872f5429507d382e1fd97521eab52018c69647c3cf59bb0ee169c8" },
                { "he", "52e00977ba9cb914017dd4a80e056f36382ae42e5b068fe8e4cad7daf20c6f2f4f6e7b39372c0c7a4e22a7a68a1ae4202ba8460e238a9b566b2e6c3ed480e783" },
                { "hi-IN", "1bd7f73b5125c385d7a8b84522afcacbef79b37e71a672064615ff0f7102df7102dc9f2b2a636bf5d785d42783abbfbb8bc65df4cb726ea98f2112c6c7f8267d" },
                { "hr", "496a3fcaa7c62c7d16cbea96dd5c5d79f95e97c92c2577653790cf6f451b21d4cb656476be7a09cce64fcda489f97768e988a1ea177b0197ac74e12fb8bc9d3f" },
                { "hsb", "e45e7a6ef664deaec2864bdd24ad1916448bc1247a68686e04e767e753b7991f5b8c15eba435f1c305b33efc6676f3bdb5a4e898959e16fa102312a5b2eb744b" },
                { "hu", "5e1f9fb9a3a097ead54ab884e145d364a66d7d00c1be36c1f14516326306a1266374321b02ee7079581604cfe301d216e2e4c462b7c5e71d241f0eecfb080efd" },
                { "hy-AM", "3b971ac0ea3a5fb843c83d4f4c869767fc2df581eb65698467f4e4aba82598973ed258a8ea6426c72c684b26081edda978c3386b82034819342d2ed3a55939b0" },
                { "ia", "e8b930170b823d9b30b0130b1cdf8440b625a2c8aea8d2c5e43384f874f6263d2bd185401db3ff5715e830f395186b865bb6a6adab8a9852cab4ec6170ea783a" },
                { "id", "1794a76a3c01a14694888a775b3b9eba72eada02cb43f68ed96af723f0f24a2f9d6e6a59d9b2f596a3cd3e651d99ffa888fa545f7dd87b45c297e93ebcd260c4" },
                { "is", "40494b47c7fbfafb8b0572b9c695c6eaaeec44ece09bdc0c5465dc25247ee6dac6a0bb7eb048192eb35a2e327e7c267572b8590fa5c612896e170bfc2be07b75" },
                { "it", "e14c58a56e602479515473c5d64ed39c897da9be3ca5c93554a9fa173f1f5ffdae445c73c1f2cea5ff1dc047eca9f00faa0f82cf31605e9f4bcb1ae7a018ad01" },
                { "ja", "832b6f116b618b5084f2883abc45221c095e262eaaa72e18ef476628166cd0a5b3eb67f04033cd0b91fa1844f05a0365807872707c60446e2fc015ced3f89b7f" },
                { "ka", "93fee71739af8fdc98c85243f1966ccad98a5872bb3fee1828e5ca3ef5baa21b204b453464db40efb09d62e0919be54f7fa8e9a9e4ae3b1236ea776b925207ef" },
                { "kab", "2a289e188a1e9d31b12af92a423a6e5fa28eaac2e38707b098011954f529cc0ef9e75d605d61041d23d13ef8acdc3b0d3525bf8aa2a2ac1d0175b32e4bdfb6f9" },
                { "kk", "afb6c94719e38874a034fb93f811136a0bb08e0a78feb01c5215a29fba47c266b5a7328c805e0a2786acc3f36f08570181e5fe091aafe5a760c74a13ae5fb15c" },
                { "km", "44a4917d0ff61432514f16550d97a63246bc7de2c957ed91ad312ab1ce0f10ab708ad133b666697f36cfe164f63aa3bbd78866e58f868a50ccfa7ec9b7cd79ea" },
                { "kn", "9b750b78a52ffc381fc50d9d6729b59147adbee6b9fde7859067b0f07f9a6df0f0fc5333f81360d100cd0eb4f13d9f94020bb7dba96430d979a882c195b5a987" },
                { "ko", "065635b5492c5eac1fafd52d19c6b5987a72f88e15e63d539453064f29945a8f6716cb3a4ad7f2a4686088ca127f3ba50890c0829787ac8187cabf990ccefe1e" },
                { "lij", "42fd306dd49af3fa0d52b234e2eed644566849f1ad1df3fb5ec9dfc312df093d3048d7379b46372d3de70506298fb76e435170c217de95e512e9ecabe66b753f" },
                { "lt", "dbce7b063f3960bda2767fec1c5825f1ce48a30020d21b21ee0f87612d8c92756b4d3009a8f9ab207ec4c1614140e84c1d01e1c5b9ba04c656be78a054728b3f" },
                { "lv", "749ba1eb078f3e8e468aa9df07a8154b5e1aae783c0d6998342fd8457cf1cb12d16ebd455e6fe35306d697165ce8bb54edb12cc1165961277b3efc088de2cf68" },
                { "mk", "a3822c4943f608c675cbc708638feeafbda5112ec5efdf3cac3c73d5fb31764971f4aef52bad08a9d3007d68f2d4540738c2ab9af5d5746aa71ff24a290dfbce" },
                { "mr", "74014d79c72359877e49a9c90310d6432291158df70b168ad8b4d8c9715c4ad51ca97793f27fc44c582f1561f4a8899d458ec7e96604df1b4c8d72ca6edd18e1" },
                { "ms", "2452a00a7418880d4fe6d848ec923bad2807e8937166ed3b020f2ebd29bfaed6ec54f93aa4e83d53d3182dba6ec97a3582b53f007daafebfa67c3430c7bf62f5" },
                { "my", "b8dc9b4c094fd82b8f1f6bb98af3a2e778ee6db2c33f2009de00049427c75205b2b0c20a079c705457e3cf5b221cccf966c3f082d3a35c390c872bebe05801f5" },
                { "nb-NO", "32354e06ee083d00207ede322e97f501c6f81348fc9a1833af7e0c86e7fe0a8b9404b13dbe1af971b6f25434a1557ef78b99834949172ba41cb20271922c8624" },
                { "ne-NP", "a661710781eb1a2583ddc6c2e391c52106fa9de2f5811406d76c82fd326de4e286acfcaee93b1848f98145b31955c760fc6199a4e9cb558a7c09bd039ae2e8a3" },
                { "nl", "23effa399f4d76ee36b224be05b4b408793c7322eeaaf01b8fa1f7f9a877536b4c0ce286a1c855435b8489746ae2d5b1fce70765355bd92771627c787cd80520" },
                { "nn-NO", "d2278b60bc84b15bdb63a0cb6d52511826de79e165f7680178f73696125257931603165f8f8b445ed0d542f08eb8ea224620f5f8c4c2d059e2368e20b1d01558" },
                { "oc", "e8df98d9c7355e26d8e910afa8fe716fc4a1fa801ad09af70fd2213195382801bea25b118aaa2a8394cbbac84e366e499bb2d0698e8ff3ff47e0a3bb00cd2c9a" },
                { "pa-IN", "5ba52701afbee89f2fba37e2a2b5edd981f523bea9b9ab20068032125a8e05ce6ca0c26747a4c83486aa555409cdbec4181573368f8a6a8a107e27b9f0607cd9" },
                { "pl", "acf5ce7f6ae55f9f6020e6ea3e5eb7082d6c9c069712b3fa12c8d2b5c009cd9946163ff61070bbffd2d6de99512814965bd28b027576408e94b199de34c5c8c2" },
                { "pt-BR", "03a5359940d9b0add6ba0a512d8054222a93ce9fef00804bbbe5435a79519cf03e4354ef9589e87ccba6aa3d8703bffd4d59fa12331c6a23752af7bf5aa74b0c" },
                { "pt-PT", "b4cff0ffcbf5500fd1afa330fe60587cefe118943bc91bc469320b1cb7be9b9a83e1e497596c5aadcce315b58bedacb7ad4361616d6dd43ea4c89084a8635926" },
                { "rm", "085119e53ca40f84cc0b24f42bde280b6438f0ff0ed6386f774f13a1a34321d269fac4d3c3ce6d20226dc1b7a68d0b992a211badf4d61993656704975f9b69b1" },
                { "ro", "a4abd718fe7b27c823474365ac7800b5540a0bfc52847f92453cfad32595b7d454f8cf498296b08c9fba32148b4ee885d10cd50704d587bd3e5e36e926f474a5" },
                { "ru", "acd231ee00b5366d6f68635adc57631002eea8fb53eb6419a0fe7a9dc118afe47c975cd8afb6aab28a12aee1142c453c824875d60d9fc748bfed501ed0b188d8" },
                { "sat", "fef64a15078de55864948b19e0b436dadaeae872c3f8f5014fd931c90fd3b47d872d31561895947d5909a3e2865fcbb70a473f25c071f2b10888b54254acffe3" },
                { "sc", "d6f1cd7fae529203602b921d6e702fe12ee62d13b3f0a0be1946b62351c8ca80b21e4ee051760de13f826ec2ef5cda705986d3782a851311070ffe8921db0945" },
                { "sco", "7a91025a1996b7f8fb89663831ac456e6e90d3ed44910eb29b92c478459035b2289ea940e888dac06d60a69a3db51e799ba5f88ab9e79268609a67d14300184d" },
                { "si", "9816d46be14f711985bc4fa522abfd4fb06b4ba6bf023d3a8057faeac6a31f668f7484397d0368cb53241c1fc230ba1b2d856a7aa5e07e4536752b35f4b72513" },
                { "sk", "af7b89d0d03cbf1982526ef5fbe5f8534ca0ac8696be633a827c18a87ce433eaca23a0997072a2042bb2bcfc2ef43959a3907421852179e680c8151694e31de8" },
                { "skr", "fcf98752d3e348b4209ec471d1d90deb7fc1cd17ca2a85f1d22f36f7aa0fc0b567a0afba7a35beccff1f769411cf0fa70a9469e09b42f945d5f649b95e7bbb8f" },
                { "sl", "ab74b3d88c3643d35f027d783424137533fc626a3388476dc74706f856c6786e9565b5dcacb0c879eae0d367eedcabf5679b6c7f8402fc7eadc5d361205467df" },
                { "son", "caa615d5d21aef1cff602db981e42308e4e75a44c4217ddd0855bfb4041263fa040c5ca0fb5f6b1067f9435ed8c66752bf25d92a4cbfb0dccf1ace2a319cb3e2" },
                { "sq", "cfee244f69fe0e36ba7eeece9323210c33c4ade74f99b008dc31e7fcf17318575f217acf8b372d368e1fd563ed801b8fc2e6de0006bf62f7eb39269053931b47" },
                { "sr", "af7da6e304d8e7a2b31e3dec766d0e4944f1a88f2c2e0408390f06193cbf0f423d7801b49690a6cbd291488e27a961e0963c6d0c86351e16cd217d74e356b53e" },
                { "sv-SE", "742eaf9e753ed135725b259ac70e661c3ee960eeb856fa4d8aa10eadda250062f4eb561ec92cc5c449bb85a3a8bc6b8b605f0569451663a80f811d53f605ebc7" },
                { "szl", "76eb744e0576fccfc547a99fad67064b0a8299581a9b4caa9f10b5071396ea150ad6a88aadc31eade50369fa4591d663aa33f072a3a6989c7c806d7bdbaeebdd" },
                { "ta", "5de95e27b9b562a1a3ff2baf6b602b59ca547e03799e615f99725bc6e7a85d375aef9d46db7b6e83ec260d33f1f48b21b5b794c1abbc19666a857fc2a11419d6" },
                { "te", "98526860748d6edefb8bd723a1fa3cbc1df2bf17897f0e9e58502a675e9a7ce395e72050af4b6099133b6463e5e73f2f05bb37c21df9c624191d4b6e66876ff9" },
                { "tg", "3d985688b59e9e2c966a4d3315721b841e7a54542c3e60c4b829382f33efa1f1f9fe970c6d3ebe6c72ede0243110ebc5bb9c8b59549fb2208942f370a552724a" },
                { "th", "2b17db5ca29bd5297264e1f2e7ff485b0398faf9dc0ec6b3f9d58f71fb565ab77282ff40c64b5afdbef0d20044347da96baa880ce20e62d63f51583e32fd18d6" },
                { "tl", "28e7158c3235251622a2be400a922fba6870bc0fe940ed0f6a47f9347863506c553dcc88b1cef26bf709bc2bfc68baccbdc960c168339214b59f1f4ba5d52720" },
                { "tr", "fc2e19094a4d6dcd5f222ef056fcf0167f5cbf072c9f0b0c55da8c1ffa4ad5a5aa4ebc1a20b0a8610dabcd6a0da72d79a15d75b1714c6df2c8ea2d0dd8f5b11d" },
                { "trs", "f378fd796ae8f376fe106e703a82279010e435f8c687a85c0ad5d90a8813358e20a371c4ead62387c8e4e34ba28c8c1fb742d72b2e6a59cb627b6c6f9f7cb2f6" },
                { "uk", "63be29b67f3144ea9ed03152453b498d4e1949f4faa4d3404ae4c5457868298540e21f389c5bdac2dd225ab58a3debd8a5c9521f9f2a879680336f2308991eab" },
                { "ur", "f8f71fd25ee802dd2e243d5cb4777c424a70c7968740ec994dd3d0b69b1ea11ee117af8c4a0b13355351e0250fa59a48138276eafac17c0c7bdbf90ce1063db6" },
                { "uz", "b314fe67be16181437df616c0669e1cba1863a2d7f5d4c57359b43d82a76d39286de6dc463d70d3650e7129b264901cf52c42f69b0c48aab3edc9b973d2b0a44" },
                { "vi", "d752de1c59278bc92e97e135f8e4e1da0b900332d6c9c387cb0643e7d7e896f60147ee8a0c98cc593290749048319f1694c5992d95bd3d0797dfda247935ba95" },
                { "xh", "b2c7deba150cd2ef30018b1cebc7c77960073c79b57bf9a144c35c067b376bbdd205dcfcac9fa0b79e486588e51504e04c583b0dbb4e28b716f5f7a055e99fb1" },
                { "zh-CN", "1e03567c750d73dcd6f2371ab5009b3e46ad346ce5410b2a8b3c37937cd580dfa49ea25ab4c20644dd27114955712eca3eebda3b4bfadea66a4d22b078c8ecf3" },
                { "zh-TW", "a90ea1b971c7966e08cf619105b0884a8eab23b545af27d90fe31c95392afe334f4e492082ea726af716e81fad10adbde19fc402c12f9aaa31555f475e37120e" }
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
                // 32-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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
                    // look for lines with language code and version for 32-bit
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
                    // look for line with the correct language code and version for 64-bit
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
        /// Determines whether the method searchForNewer() is implemented.
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32-bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64-bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
