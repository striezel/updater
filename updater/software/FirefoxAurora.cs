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
        private const string currentVersion = "133.0b5";


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
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "eeb7692a88e096a8213c5d25239e42579bf321366ee519e162800e80a25f3c47ede481f324e23bc3f08172330d37a9ff15453addb92de64c2b1dc28f92341e66" },
                { "af", "80c3ee80086ac6f9b2ab64d64c65ec126db979a1225946f0ef614989a1c5c9e1cebe79d18ad4c4631641b19fdf318ce8f68fbffda35b7ce6900e8ff14e72b334" },
                { "an", "2cbc96ef5c2c5be555499dea95762f32d9b834633609b9eea4e5dec3548a98b1014170df1b8185fdeb8f67c28d684a21f8114a0c38a1e65e13943f9d199ae4a8" },
                { "ar", "5e41bb6bb67b79e571af6a8d3f208a6c0a39fcaf2351fd003dd55dafc5b08ec21e2120f1483637abecdcdc3fbe9cda107641eefcc283bc85fb386db8089ed219" },
                { "ast", "e3bf216b2547612eae4e81adf46241565928652d3c64441c137234844c01c226320033917c478b97ab6801a5dbad3143dcee8aad9a10fd87be7681ebb13557a8" },
                { "az", "f5fa31a7d2c39a8869f06987425a19dcf3736ab707565a7064de430d7848c18a72c9a425dc73cc789938e599b160736962e59a5acab55db0171a56a250f73ca3" },
                { "be", "f7b393ac3392d4e9f289dbcf566df30d22cb73081d82290c6ff8db6dd6f5ff9910fae9ba1f03676fee40cc4a6a71be492a9bab2f57543794947caa3bcb909d66" },
                { "bg", "386002e8dc874a141c34710ce544f3aa967303bb62db100c9776c827e8c48b74f0dc477efc197b55eef8c5e38881c61169947f66a286345f087d341a3968ba83" },
                { "bn", "50854d0955c91ae65c211e5ab473bf3dd93677812de14273eae6ca8591786c24429de1b176876da83b038ae35b25872cfff22a5edc6c65d4865f5fe8d810be79" },
                { "br", "3c2090502f65e1de9967fa2710b3c72c46b1cc430d6a6d74df0967681ba6ece9029d897b426796ac430dbed7c4dd81bb0a4732d609efda8ee543a97418d885f9" },
                { "bs", "b926cdc823709a86471f795d0d157c0cfda33881e723cd5b57c602aa18a3435e5204359bf10e4b44833a4c0ab05e6197d2d11e5ea9fee25897dfd24761a1b97c" },
                { "ca", "31392919f1d74bdf05203f7e5256484f98f4302977dd25359e5cdfaaefefec64db051ac3372703bcab4905513c54d006e737d0d2d264ae8d28a5f2eeef35e5e4" },
                { "cak", "fee2bbb9a82877bc3814715a14cfca20014de9b0f36499a203f9a302fe04f27c0ade5e2595b867eb39d10ca31b792768ad6c24cb494ec740fc6db799e311c672" },
                { "cs", "f4ab71be9bc245e75ebc7da1499c891310743190d0ad23af484a783992c6c29b143439e3be09c9fafa009d1f652b13e66acb65c68058ee38f36cd22e83571649" },
                { "cy", "faae2da41181d9a9bd4efe765bbbbf161d5f8b4ad6521d516fad79e0429e21266d01819fe89c1370db86556b0d6eed3c744139748f5503742c7a63abbd599d6d" },
                { "da", "b812cbfd8a147fd2089d57d54f2761584c69e02671a1903b610b6a464ae847e1b0c16785332d52d35aee20cece1635dc0563eb2033e3831d1c6f61651f2e5b6c" },
                { "de", "b67001b803230fde7c98374f7a0a2d01484d6c7bf2aa554e0a4a7a1c234cddf7ec0dd55954ca2fd54941b2df37c3669bad3993c0ca9f659ed0992505ddb24fdf" },
                { "dsb", "b798d96ba8a31b64b0e24fbd43a8da4cdf62acae7ef27952f303ce93eccf7274f87fd983c71b55a431190867d0d794cd282028e4e6ae02089d55e8ee19a6e7a6" },
                { "el", "e185488034c9fda3d6cddd4ef4fdd7b79cf9d7f0ab68e3f2f7c2b405123396eb543f918d20260b7b60e22fcc1e16d059b7bc088ea19323aab257a2c1903126f4" },
                { "en-CA", "f1e03e32bcf10f0d02789dae98dbb5869b595474f8a2571648389c4e5a5dce6618ead9206cd65a605d98060c073af8258365463c875ad60c69d4aef14332cabc" },
                { "en-GB", "0c95b989db07b56d7f6d04bde6fe6121ab97bd0d63b5fa2d8f142d0a78bf6ff28265b6db90f7b807fca75f4ef435240bed3c381f6737cfe6dddc5062e1359686" },
                { "en-US", "5dd6806266f10bad68ca13323e7361cfd405b2ac5a1afe491270250533c30ea30124987c8024a83ae0b970cf0f2a9f26702677a06b944c7ac87f6b160eda7bf3" },
                { "eo", "1f473da3147164942db3ba9c58a27a29e525e5993c51c40be85c6fe86332deff0af6a08297dae56eb05cfee0ced0b1fed673fc02c1ffb4a3b3b488881ea00fb1" },
                { "es-AR", "8aa4d1a8d80f6f48002ef875f16ea6b01f5555ab5e9bc93bd347f77b5c54c2b53c278b3e7f7df6d94efa024a97699cd6cd312100144df2489fd88f0ba082bdf7" },
                { "es-CL", "a44e8a0382903884d41096a7244a451bffd1a369da53d003dfd9cfdc4514ee546c5e6eca48fa22a3055594143750b7ff6808f6834ed92abed63844ecef3d785c" },
                { "es-ES", "1025907df0620e49c2be28b4d3bd9dcac63df51fcfd7fbce42f371e44c8a8d067a01f15b6f4c7cdc20040b5d0a3b90ba6d3a06c0931e58f2d75a288c77bde833" },
                { "es-MX", "5fa9f572311f1e84962c9d667a68427371b2e87dc95d744cc3b4185b37c283bdcde856ea32d044c7bc194fd0a938dd38098090c4041483b34571ba222de01904" },
                { "et", "48561e4af6132a6ac669976a7e7730f9533c513478cc9e9795c0761739543aa99d48ba30faa02493716ab0e6cc77cde46a0f299a9b83a78c20e309597e68f807" },
                { "eu", "a5c034ea03cb5018cb2638fd23e28cebb646e803cfd65fedf9ded335fcb56aa8c60feccb7db8477109a99beadc08959187fa769b62d554171569d1bba997d3b0" },
                { "fa", "64b06c51ba7fb58b43eadac2add96c2393c93efb0b6d63120f7dc2ba5d3cacb4ab4f3d1c739efb7ddc1eba70fec196687f67aa1a3caa7afe392f978f279b6990" },
                { "ff", "122078731ff15bdd8a0af4e3dde5a1b81f89ddb7d7b77c1b6c980ba5f9d044b4d0cef0c0b82a75656c02ff16186bd1ee968c8e1ed46603296bea78c2ad2b82d5" },
                { "fi", "61aa42450a6f58a96ef58daac43142f5585c31f202a48e2f0a4ea3310b54334121a39697eb1a869e69ee9d187dc9a2a54a94efe2c834fcfbfda6e8cdd439b609" },
                { "fr", "b8fd5bac7d930119b281948ff0ceaed516fe33675417c9c803926c92d53353b915c2bf970727ad0286f32e401af1373e6a45b61e6ecbb9b8dc6f0d8dff5cc13f" },
                { "fur", "2d7b2e7babe03c543c0d5506719b2a020ec576829fb1537ccd1d837270e5213304415643dfdc31a436348a284377c083d69f4ca250f4965c371d1b544f448295" },
                { "fy-NL", "a5613ff1bf117dc0b7cf744a4eed3edf46d25117ec33c1669a7887db4ae5c17c9a820a345d262828a564c2b6dcdc54e6686b0c9f9a27e824a2308ea2f8ac08b0" },
                { "ga-IE", "d30150f756df0624f5947d384aa6221ccdaa93ed3995bbb8c48b21b1d0a3d792cee1af51fa19a30c9509deb9c5f56c34f4f47c39274776712ad70d5b192b7f28" },
                { "gd", "964b044b2d0f80189a95f23e17c109091a130ff7c14fbbef4f40c6373b90fc96e7972009c93e5ec0796ddbaba6b713b6e6ed219c53abd4e45e5c057217ca2561" },
                { "gl", "c5855a3a18a86df8085a25dc9acd095d9a245ff73e796485c825a5976063ed5547b2e64377a723be54ae5ef1368d92a7923512b0660292b98ffa664d5366eb01" },
                { "gn", "bfd12188201c429f4bbf1c100aa63abfe67cf0044ba201a258a5b1d3099730438dbed5f3b822645417b98e66b09ab15c404246d58c91a48a76f0931cb731df93" },
                { "gu-IN", "f847ff60a41cfa7336ca35ff25fb07ff189bef4873f5c17bbdd3c98e61821008bf47647413c229f000a63988af08a73d6a2d7c90b4fd976141270ab0774fee0d" },
                { "he", "0c249a38af3bbc4a3bf66c6db36273c8edee675b15e889d42e9af18b3c69e4b65804d34c188ab27278e3bb45edca0e3cda8e35fa2e9a4138d6b4d8f059dd9e1d" },
                { "hi-IN", "1a904b8f23d6de163d3996f31e6c22efac34e99f4e3cf6b52114c46d1d67cd981a1f0f2e8129cbe455c479225b8fa3c4f380c2631bce10f2b65db5bde3bc1b4b" },
                { "hr", "d0d0db7601c2a77e5f6b9f9ae216791520c551071b0f69e54b37173cf9b88275ed988aeed48b61d93a6e9084fbf684da0d9930817416248ae8f2e2682666e14a" },
                { "hsb", "dd042690ae920a173395be13fbeeed630a0cb1157f885d5468dcafbc3d2ba388cf1f7c17935aee2ef2808c157639c5f5535430a77dfbb38b2eb0079fd1ffc58a" },
                { "hu", "578cba3eeb55a082b55105bf8b97bbea163bf727565d20536e089839dc34e1504c0042ce1d0190275bb24c30011f6596af7f7dad3492a06ad095ba73195481dc" },
                { "hy-AM", "d74f8edfdc1d36e7da3b031996da2ec378516dfeabe086cd15d3928c573b29ab80ae0083574586df0e3c63a5e784b822af1aecc05e95094a50f832292bbe3913" },
                { "ia", "209c166ac002fd58a8787d07a620bf2298768a57c467e59b3570c90f6a6d01e94a9f8e7d753fc20a6162841718fb047dc1ee672dd96d3f33c7432089083a48cc" },
                { "id", "cb5cde86330f7cfb8514a7619b185b8776ffc5f8c21c3d6336f24299d79a115d7c4964c6bd49623c99515bcffbe3fd2fb24ee685a793b2a9e3facda52cc7b016" },
                { "is", "54633485a46934e90b9637fa77f360861610cb9624af5d05a276255b3ae6eb56de8054fd18fcdada0fb3d2c05f73048346cd4d2d6d2023d6bf2c22822b949adc" },
                { "it", "674cb07d6b4605604812c9b2b7a5255b41236d020334a239069242bc75eeada44d13c79ae428866e84c77d74df53d376816d6c6cb6615e898b5e59c8aceba98e" },
                { "ja", "595330f0659562b4dd33ab2a6fb0fac1a8d03a8fdb3d9ff99e154a377f965b1e001919065b1f3477620196d44175d011070c69addff456ecaac3989c9939106c" },
                { "ka", "f9cbd5054f93c342e8b04703798b6551a3583968c97aff1929feb0d413be58f53e8350b0f28178fda2fae91ebebe168418e069aeeecd028df21b0ff8ce4411df" },
                { "kab", "af4fbb467d8e28be0bf554cd5d760fa9ad779e776d315b1d425f5eb6b668f32fde2b63be5a73d41b5edc54eb84e65e74c5825a472c1fdb24406e943e00d4c88d" },
                { "kk", "b437bf92e9341b262eb421e907266886f9f7ba0856ab4f05034224469d79b19b44df8a530ee473f38d894370e347668f256cf93346c9200dbda21f5edc9629a4" },
                { "km", "3634a12b4af569b3fa4b40870b37345ce0f7c61d342d2090087b59e01f27db27e3c8a8f392a86d0417eeb18bfd156e2124528baa59a7320b1380996e7b6a289d" },
                { "kn", "f47c5dd41daa507f111eec4f574ca3f9857f5f79e61ce28c49f38604bfa815de9b4c5a1c6a1e07a582db7fc7760ff090c9ce1e6dbe1ca9ae73b4a6bbd91a3870" },
                { "ko", "8172c0e07237877b2fc1b3360bf4cf27db8cf409c099734ade41c9e1e28f7c2236f2b2c5c85379adfe0ab2f6e74b55ea57653d9dee6a3f7f610e8e42c0c3c983" },
                { "lij", "b22ea029ca6d3102ceac6d76b39a8fd562c783e2e8eabbb2cbbc8744b6b9acca91006d0cf39363da37676c06649859167548464c285d837639f61fa7b2a376a0" },
                { "lt", "c8488daf545e347fdaa29451786bfc03ba7adf2993c98fd69d8af5e7a03041102ed802dbf4d5c1458ebad4ba0dfbc3d3d9669532fcf0522bf1ed5c2f8d7b9e28" },
                { "lv", "492f809a1df8979221c155cf6169e99bee5da958f30798b9c6f69b777beed79aebd74ea27276bbe949a7d07d617a2fcbc24b6114ba9dd38022b50329734b4ca1" },
                { "mk", "4d03b81f2dc8989f9675b1848968ff9d4d8d043942c7ae11d45e8f56f579d367c1dd95257469cf0968ebbeadc45c3d7d7c228854a650c57ff777c03529be6022" },
                { "mr", "517183240718fe6e8ff55f1645a0a5ab388f9df61ba87058f88abaeceef0e5f6d7cf70c4b98dd6e811caac88b5091605979ffde235a74efb60b6ccd5a282fcbe" },
                { "ms", "06e98f185b6de1b557b623da7ed872850e522b3512a7b6b8efb08e15700923b82b2a52b6051e4300f8e3c71e16a6dabe22615afa7973de4fa5c64820bae10770" },
                { "my", "33fd1fc5c1ff26750d665a30c65b5555910e26f6644084bfb8f1806b0b9527f95d68f8acbf866e02332e1697be729bd85dbaab1baf00d06035f2f8142549c5db" },
                { "nb-NO", "b6a566d8ab693de9f4738d6606ea926a52c73a90006ccef061a2331f286dea864508f3c1aced934f5f332a005d90c407c5e760bb20c409e94a93a11fd20d41f1" },
                { "ne-NP", "8633570c2bdd9474f1bd54804a22a4ab9deff1292a388c0938ac28d40a5ee60f3275af0f2cbd30b92e63f9ee69c4aab995fbfebb15d202eaac79c83ac34ad3de" },
                { "nl", "4f9b7273fdcdb9f188ec42413effb2aa4b92174e945290cf7092137487be222665bb0ca42cd557eb2809d28443fb52366be32b9ee5c7d4c863ce665edcfedff3" },
                { "nn-NO", "f50d499c367129a99f02dafc2eeeaeb0e7d8a33351e0bf953ac9d6ea7a7766b5611d55bcaeca65d5cad0d5d5f7afd63508afa8426d57081e50ec4132abac73c2" },
                { "oc", "51e1a73e3ea711f1cc2d3ccbac79fbf30e06fe103993c4342f519a35a219d064e72c22f8b98195633369ee691bbc1ab99a1d916e2ab7aa1c1c4428c25dba89d8" },
                { "pa-IN", "c1375abf8aef3e783c48443ef56e0157152c0258b7f53b230046062bf6eabc2d4a36f3249d1e90d8ab1abc159bb9bcde651368e7c950e139f6b60bad6670236c" },
                { "pl", "2e1845674942622ca8ecf2d5fae783b5d245a548cecb487c57ee4f84c33a4f13a527b881978c8de7609af304a53fb1772bf73cba84cc7636d56f013ad670627e" },
                { "pt-BR", "88f790a3f2254b64240cac9211f337216bf2cf489434159cf31e5d5a0995f7ef9448aa77317c219565e74242d38cde26f2ff91e4e70b210a1bf0ffc069732b78" },
                { "pt-PT", "4b41620cd896f191b26e39a125b3710b2fa52aa921539fbd6a391074d67a099ef6eff09eaa0094b14312032150bfc6aab988d1fb22d08ebb95aa0936614f5663" },
                { "rm", "78d3b1c65f35f2e1a84a4f6f74afdbf7f74accd594a0d9de802a7cf02b2b09ceb1f7c77df6e683ed96f8aaa5dd4309bf9020d4698e2339eb535f2178cbe93793" },
                { "ro", "997fc4ee4933bdd9bd11420fce801bebcf2711c2d0438fa66969a682bbcb1a601060d5ae86636bbe82113f220168f3612218c6fc349ef927da5e1ecf7b934b27" },
                { "ru", "41463de2130d971fc0ff7a9b93175ced917cfbd23bbd85eaaaac5e40c6b9ba73568981023f885b40bd18dc3b2ced6220adc4093b2931a968b94ace93ed9516e5" },
                { "sat", "5a27645a68e9f5e2b60f39cb243bf79eb7c5263dcb05b1cbf0ea27d5ab141387cf0d6f9f1ef11c5fbd5ceea4f9f9fbc5a3cd81c6fd80b6788ce9ffb12cd3d450" },
                { "sc", "e7765d6001749bd5ec057572b6cd285260461e5bb8a2e872735e5de3742f6771a6f4c9e7ef12640d1019f2cc542f1bf755842206f1e825cf91b375b5e3429b72" },
                { "sco", "d99a5a0cb6c89447846f9de56ac06edcdd12d253efdce689eb6a96b8e8c38784c3954d7a07c5892e2b0a73a6020cac82450b90f9f2662ddd91965491c49f13e1" },
                { "si", "aa3017235362b5cfef51ba4a5e7b21ce2198ffaa21328ba55eed178bd4bdc31124baeddece80fe235d45ce9327d0898f5e020f1250cca5012f46cf55b3bc0722" },
                { "sk", "179a94edf3a8d138d7cf19b38f10cd298900f877ee8117d14c09b6acef354d63a2467073ca596d45206e5e7693c3f776b203302622aeae6395a4bc291e80f51a" },
                { "skr", "a933d9db15b9dd510120657bdfe0c09b383a54323e1fc503324b7ebb817fdf6318b61446bd26e0be012ee421d954a0ec3d91d7e9b314b0e21142dd3bb31bece9" },
                { "sl", "34193218d983013ab5194701589d41a582bd48a30cf81d2f71f143b5d197e381f642f23039d7361f9f28775263a016202f8decf3d5de7851ca34975b56c7500c" },
                { "son", "2a30eeaccf2760d6fdd8e1ee21865dc8b102db6739e7f9c724bac36f33c8f58e1539f0afd9c7a51ea5b4a317b6d9a8eb4daa0a864f2dd5fd440e9a296d3dbd44" },
                { "sq", "2487157857ec3d18872fd6845ff65341176235d59bb3186419ed128a4287d5412f4173d4a189355afc8c1deaa07b7443da0d71011c38c21caafeabfdab0d649e" },
                { "sr", "7927fe06e31e1a6ac4cdd10b06a39a86436980ed5a9c248ccf33d57f9f8714900379190969d86f492febe75543b4d669ee8406f11859c2f6734e2d5266bbe519" },
                { "sv-SE", "fb96ddec7af552b0fffeba884bb2653a4c27df39457265d34ce6b92b4e7bdbe5bb3a23ab612e947670fce502d7593c4552a0a59476936feaaa0b461bb3dde6d4" },
                { "szl", "cc296c919428f1d08c071954f486fce67d12b354f57254bffbc9bd13f474997988f22f24e41b2eb4689c2f2382a607144a57ebf8b36eb7876246c38d95ebf9fa" },
                { "ta", "eeb2294e37a876a4cd1c77c926c8247eec85ebfc8c3f75f0d60c8d73aa019ac0d80d711db0f6670c4ce956c28a59917c4ed95bf80b5fe3fbad947ccb68b1b257" },
                { "te", "0544a13b6751af04a4694f316958652a500a122730fcfef9b334f07615c7a5b13b59bbe67e6ce57ec43bf756600da745b1421c2854f297304299b5f18b31ecbc" },
                { "tg", "7297b35dc2e732eac48c8ca3b982a6b4b357ee50a2dfd3dedffc166ffe36a69b5d5b70b47b059b1398edb7dceb489eed16e8327838f2480dfd20afc607755c82" },
                { "th", "187bb83f7023671c4b1d67da1ddc6c46cff92515fb430ac4b3e4db4d2ed14f307a1288c852863c43604cbc7ef7d9670b8339efab2f6507b3760ab724a460b653" },
                { "tl", "8dbdebee6612294292cd615304954b93e57408bf96b97e6b669df749ba544ff6f440ced18f57042e20d00db766c0d2c32a77145fa35604f2478eafc9f4d29eaf" },
                { "tr", "f556fbb29da88f69a05737e9c317e0096997ce6e74d29f18db099acd0ef08855d04396c3490fd5bc2b51572a00027142fe5b4f60c5b39a5a5d29c7970a918cc9" },
                { "trs", "4f866f401c8f2048dfbefcfc418f74535b9b8233f4dcbcee1c96363635a6200da48c476649caf91d00432bcb748145922dc3fc8b67068255367dbd71356aa911" },
                { "uk", "8f091d81cf7f9c34d0f6852abead653cd63ad5fd4273d9c4b6710680d5fc83d13ee6601864cd5347785a8bfcb6e241d07959c8623665f4e53a473ae0f91d2881" },
                { "ur", "06c3f115e5765ad077afe43303370dbc83892ff9f0d862d9c8c800103541fe044597bfcd7aad90b92f99f3bd5479664242f3553a698481257a3b4a45874b927f" },
                { "uz", "94ecbca84ffd038673afe04976485c631fb568451a8fff92755de6ed3b99ed80207935673f9a54a514f46addf6e51febc3859d16eb57de999d43dc9e9745438f" },
                { "vi", "1f3f5fb22acdbce63aa82528467d1b76fe1570c0f5a1bf77498c19933753e7a07e395a580a5f4e950b5ab389ade85f54204ba8cc073213f9302461b355da6b9f" },
                { "xh", "6573d2b8d9ad3060beb8ffe390980a42f88eb4c7e5c897ac250bad11f00396fa6681defedc3f7750fcef0790c8b8d1a127c665c49b660c302a18bed6f188d8b4" },
                { "zh-CN", "61f28ea53bf03e44fa42242be426425c8d3280942455da69373c697ed46cf8096bdb0066f87b3b18ccb4142709d667c9ddedb522e1624819ada4831534bf74fb" },
                { "zh-TW", "4049d623d43e4b0b04980e4b7461f27a249771de5633330bfa97f5609321922845a574d6abcf780ef4c500c745653b8441dfa549f10115f936839977794499bd" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "048a29d28399b139fe15c39a18757c4bb992f71422982eee5aaa63413e476d9a4c9f3662395be2cee13d08802a4e38541aeded8b55b49160974ab50d15d6116a" },
                { "af", "afa4095c85d135da97422c5d3b9dea3783fee218de68f3314d44f482a88f5a118e597d39b15b41dc63850eec9eb8fe375abe9a911a10c2b8354e668c02f940e6" },
                { "an", "c2e0c36362f72e9ed0ef09305fc3e19b238e0dbb533e2011adec2ee6811d60a1621fc80b78fdafd219474be45794ca8ab3c6841ed500c8b744cbd5796ff14ff1" },
                { "ar", "5fa779e57ed43d1627515edfe5c75a40476616b66422b3befab8dc130e630e584ab631b76a6cca1d82fd63beb4f318490c10c161c2f73c8b151143f6be9765f1" },
                { "ast", "4ec9b1df6d4252b16c8d6584289ff5a4e08023e6333f5cf83c04ecc12c0adecc11a0d0fe149c715a5b0b437bea3665434a8bc60b5c20de2a7687bd641d7e3cab" },
                { "az", "b2ec0c7e9c7f847a9fcabc0d102394770d10cc43f1c2dfd65d47e53a594acb5de15dc1df7056c7172e235674281b17aaf02d26e457590429aab62153a1c56055" },
                { "be", "8a85c6f05c1237b762d3496b2f048f0f087bad6575ee90c9cae600c24a1806d6a3b1ab1136b708319eeff3fc1238b59b8af5279779cbc85ec5fa3f72c1f29d82" },
                { "bg", "4e7535deb415615f3e814b7bddb11ada53d57dd2d78d9c06a8f07dd0c1f47d06b07e34adbac968b0e37ae04e5b398ff5836444f5163284ca8e3c22c2f51e59df" },
                { "bn", "4fd604896d69300d62a02059b4feff0f94c4cae1650aae3c7a0da79753c94d38bd7e42e4aad5460b13044c16d95d20ed062d15569e715627604a59a284873b35" },
                { "br", "032c90535655a72e14229bef2ed0ca46097a7e6961ba25ae6620b99ccc4ea0446b0687dff754d6908b51a2c004712f24b561450afef0aad98d1b519a93053567" },
                { "bs", "0bda7bbac666e73097fa8ecf52db0fa95e1534bdd9476caf7e090113070cbd79143bf7152fb146e08db63c0ec5b0a22ce26535502e79ea10c643ee9a63f27c79" },
                { "ca", "a96cd7abce58ea2b3a917976e8ef53b07b2a2e72367b592f178219845c418abe0508d758f4ecb1b623057dd20abff52bd430d2c1282c487b6c0779cf248bac7d" },
                { "cak", "c2fee0d93d2009be9f6c8dd00374a7948cfd71f2adf5663b8aba17c7f6efa7b9bfa6b2eb1866c270152508acaf287d3eee32dc9248f10b7bc675a8a84067a793" },
                { "cs", "fd07e3e132fa71c5b6cef281bd099ae8f88c9bd93e11c0269ee95ef2b9c32ff2814d12d6f39edbc47b7b48d466d49ab034f9a1ca679e3baf71886f205c8af761" },
                { "cy", "8b7c01b27c6f5ae359b453bac0d5ed69cc0b35e781eda47880e217838a359313632ecb3f5093ed10a80df1aac19e8898078e041e62854de30ac042452dc7f59d" },
                { "da", "fcfb34cb1e6eadad299b9bbdb54543fdccd236ebdba150d1d35cb446a8fcdbd571f74a5c839d58b4c5d08e576d0475feb6dba46173c1fab471987f2d8d62f507" },
                { "de", "8a49c316a31e583a9baa7b5849876b37b5fd1815e3436a01cfab5f7b67413b0d10f02554d85f78f9dc61d878a0c0697c9e34740d119c1fb225a850ba8fbe8433" },
                { "dsb", "bc60990e60959b367ac8a24d5df67ed2c9c43659a08359bb7e8c061f040eb667b7ff4586c26124d1fdb23daa3831bdbc9addd4311ab73bc223aa8a405cd782fe" },
                { "el", "0f8d71a890e93e815d89b389c313b9700c9ddab7b8747b21e17f70345aa7244b3b708a5fe16ba352ec91a97c202d994de756bc025e5bdaaa90575e83c7360d0f" },
                { "en-CA", "b5f8e76d836a2fed0b750cdd48dce9cfd15b52013e2880d7ed0bc35e25b86298e4c40e8a0e0ef957d3525fce51590dace41d524c75ec561369194fb4eeda0f33" },
                { "en-GB", "2a94eb3e429250c9ce6db0353e0f2a85617648bd4b1837b950f7482ddc013a7a34177b762a8662e77830ee4bda15468b7d91b3dabe761f2dcd0e4e31f7f0464a" },
                { "en-US", "0b3326eb8f89a9e4edcbc2aed3dd1d08588149ba3690fa406158ac44a0fc15f903d1b699b1321b06075d8d5e010e1c6d28d1767588ccf7d281183e71d9a6ef3f" },
                { "eo", "5b38cd080b14e68f15331b9c6a81f5259aa0f560957bcdcdc3bbff26f1da8143a96598c5dbb05bf1c221bc1767fc355e7b4ab20668de45568c0af2bad71ab6bf" },
                { "es-AR", "04666d90ba24d48e384b55073214fb3b4b9ae4365066698e5085120e0f6ce1a61b6b5cd880db26430de48ac3eeb0f2cb19242aafc6da694560717117a0f1ea4a" },
                { "es-CL", "277ee9770368e8371a9a0c415b9d8bdab4f6b54cfff0956b4e89b7104bacec47128b8014dbd3b58c8743e32d81e5c620ad14c5508c10d872b68242ee5c2ad404" },
                { "es-ES", "8ea955ed0b4ec8693522ad54bcb70841eeb2a30d1a565a4c444414fa1221f6e1661c87bb1034bf2cb233eccb850bda2819dcb5deb011e7b59a52097c858039b7" },
                { "es-MX", "2f2e7e24b4a34262e4ee1c40df8ceeb56346fd1f597c243ec68c3cf7cbef32b577b55dcab8b66cfc74a6b585e992f136d6ba95a39ea3ca4a0830d9c99b53c12c" },
                { "et", "7dbb60f444dbc6e94faaf23497ca7bd777c1c4d22ba9bb79651cec665208d9bb800a14a1ce35efd97df3b3c08fea4318e16a5819fee050c75e92476fdbb660c5" },
                { "eu", "80054987209075fc0ab85a7b6d1f8cc2a94cf83f1d6695511f445391d23f4dd32a5c06a82f63d0088a697d4b32b4e2c7bfe9f624c4a99a32016e0c8d089575b3" },
                { "fa", "c9ed5feff9a87793945357851eef475c8aaa988e0ecb92c9e997b1fec99157b25a64fc6e11ba2bc49ffeed505963e9964232a3fca57ca991ea117a112836cba2" },
                { "ff", "743ad0338b01a151128609f8db0ef4b14aa24b079450e8783d090caf8b8febb1d10fa0ed4568ded06612fa98d4bb7104e244749d46b762b18410c0e46eafa378" },
                { "fi", "747b52f47379f682edf8ffcca935d90397374bd3631fceb37b272ea5e6b0e91bf52c3df0c589638126fbd27c58b8d3a59324aa31103c01e5cdb594818a6e8298" },
                { "fr", "959ee60d2b5e0dfeb83292c900a0c2331cc0e0ccaa778c28dcae521607e80e4ebfc1a06a79bd5b2e120543b80447356518f2ae49fc8b96a54a47dc5c93bacb62" },
                { "fur", "d150851e436ad4e8518b81a5243ca985c37433f5b878c839f76164cfc32e6c98c137814f194074403922bda82949a6fc9d6b2fde129f8eabf6c1d25c0990970d" },
                { "fy-NL", "e4c6a8bd64e40f19a8a2cb0c10e77faf8d006d1b7f964c96f8cc55832c1bac6e6aa65a8a5ab42aa2267fc3c718bf8b34dc1dc9162083b602c79a9e5cea9553cd" },
                { "ga-IE", "25c136957b33a7fffe86005d711381456c9292040fb76912ebbf061026986ebdd85d72d15cbeb319792d2dbf192cbf18a916f7a6e7c13b17fb98ea3da9e97269" },
                { "gd", "7a9bba5a544cd173831fe95175ce23184a0ac4959f41c135a5394f50496495bcb4bf1b78de4e193b338844205621bc58f592c596bd0a11df8af284f530e2b515" },
                { "gl", "71250bd81bdb5d91339d75e449b5e6199b9ab81351a485a4339657386e90d8d3edd1044641fe1a928f84f1f61b1797a07fd43eaec98de753f16dc55254c0b8af" },
                { "gn", "80ac328f49ab863e3cbea1c9bc0ac74c78eb0c076f81110e81ac85a94db02e7cc29014aee560bebcc7ab976cf4e0a82effc085d700c368742424a64495d6c6a7" },
                { "gu-IN", "3b121f383495fd71cbc206f81312a211770a2f03fcd2350a99983ccd617664d35ebbaf09ce01891c938f9dd8e8ab7b6653bbe25f4e2d11ce5d8510a668e244a8" },
                { "he", "3b16a49efff4015c8af09ab8660dfe951c31722804732baac4475399a9e87a30c088aee1361725c4e13f9204830fc9e77b0a2ebfe7ce49f4824ccdd6fa878112" },
                { "hi-IN", "02de20f66a8565940c30a4273e2c198d2db509e4f9cf64ba7c1d1e124c5261a85ce9cf267e6f8871f68cb2d1c72753d22e563ce5d4c200ed44e0ac62e8f8b5f7" },
                { "hr", "a9eab25f17f65e2b718a6352e16b41045a83c7f6ab43998e8107451b80f2c02ea036ac7d190e9ba548455496e4c1ec5a822675968d8b77b842c5fdb86ba433d5" },
                { "hsb", "c3236348c36834887d4d249bd52af8eee85b12f4414b86b162d60e58b5055522cfd0c190591ed737f8cadd8c3d9f9ad59a6ee3af1cbe202c90c2adb4ffb48e6c" },
                { "hu", "a7930f973732c0b459e707b7200de8c824718f2e2b9eacf7b0c2da19ae70890489e038a950a47472276d61ce2d1120648a23a662757345943f0eabd8c0dc5033" },
                { "hy-AM", "22a73fbda4d7b0020a035b9dbc8a5682787c0af61b44259d2864fde8ee21ec3705ea1206a3b071896fb5d81a07e2fb66b3946220a79c942b7804313aa1552a9e" },
                { "ia", "744c4fc9b134b203d3323341f7d5ad0e08babb41721434b6e091da0661e9f50ee5647b802bccc1a67e66281e5ff770f768801b1ebb04769a5747ded001d160b0" },
                { "id", "b79da87ffc07fefeeef7fe88dc0642df2baebb453d1c3c890d63f62028865fcc08f324a6a14afeba10930c7834b51119de6b6ecd896b093bb272c8abcaac7b41" },
                { "is", "d8f264d94e19eb5b65ca5f7876f7f3e0df407f837d01e95f75fa7c9fcfd8bd474ef85799aab039ed3a7e307b21f0c34b4def257d6c0b2893b7ef30b79cbcdb2a" },
                { "it", "20265a50e750a6919a9080443ca497d6487a0b4695455462cd008d281627e0dd2f55433fef6af9d068fc6424af3000e3934595e64bab9068c594096765abea76" },
                { "ja", "9a8f4a223b70a3769f3fa8d319b6a9bcf9f1e1e9c234fbdf465d95428fdd5759b15ddf9499a518c4623802db4c8eb107e871f94228c02f4e0f6743e8bfc7a3d5" },
                { "ka", "299e4d7294cd68f699fd22decee7fbae7e77d32e0efb6f922e6890dd28510737d15626a7b6918658fa209b3a395fbaa3f3f2a028253f38bf2c7608d4ce57b948" },
                { "kab", "ab634aafbcbfaf98d67ceb947830a749257d295f3b2dd1bd9b7bf61940c6329929cc1ff764d6e5ff5dca7933e4faec51758547fd44dedbe862ad17230567f3e7" },
                { "kk", "57311c8e5c4d041f1ac24ed662b2ae475f4733faeb7e3c9c29e88daff158a0dca0003f2c8293647db998cfc214912e108fc9a7c725deac00ccc55c48f6f864bd" },
                { "km", "c36537d134cb72133ceb564b43a515b3603ee286042752823a61ee84738dc08af69d4d7558735f84d9a4101089a6be4deb1a0d35225ed579bd6c150fb5c48408" },
                { "kn", "dcc74662924c0c77dc8dd91408e3ec03108b312a620a60e2eec006421793720324b741db2c61d690df6804215727cdb11e5980ef63fb5c0f80910c46fa922960" },
                { "ko", "167132b172ad4b8e25ea3ec2c2fbcefdca943f70114def3b286bc4f1d65929bfc395f9449e67a1867b0f70167ceb9dfb2b05f3ac186ca69644a177d74a030f15" },
                { "lij", "69786369aeb7eee3418f39d87068353dafed55bf2193622ee29fe371384d5bab6efa194ca5f83218e93f84aec804dc0afe237a36988407039f15ed657462f614" },
                { "lt", "fca5b543ed2257339a78be5b90d270a5564374d5f74c68ad62876a1e8f7491f7a1bb676d2f823defc466c8727700a885f2c647bcc1acc41ff93547b79c6c9f4f" },
                { "lv", "0de3db9a9f4c4d42e3a3a813955cf3a977799855e0a26588a1d244f406e2d0e40dd1ca727480af75e554c9ec15090c59c1a70ca59ad3f3f0a46605a8d721e630" },
                { "mk", "b683daefa83fc6c1c1c094c0227a1e6e2150feeeab9fb1343f1c28e703f0f2ef89ad1e1fb5680d5ce757af62ca5ddbb652f6cebb975fa24e8e04643c90e05a6b" },
                { "mr", "1babf4b3a0702ffe0ae8ce674af324fe70591a029eb752225cdf328058986cbfb34bfe4a21cc041278f7ee400250e1d5a83b3b8299a0056e3e3f33c8858d7a9d" },
                { "ms", "05b2f09b7f2df45464748efa2fc2c58e820d87d743d39dc82dd861d996128443d13b9f5b49548daf27466cc1ee3ef3b04155113e6f91478c481deeee72e8b963" },
                { "my", "f961496b230cfde427d04dbbaf48b75d55adfaccb3379a494bdda017ab84dd02d8bd1fe06ddae12ada9c6286333a72bff3b4a387d2c9eab12f3f7380d9aec20a" },
                { "nb-NO", "c11074097cbeb206e447740e05739e70c0b3120cd94db5bbf5ae3e5627c2b8f3d433a6e85c08d028468681010dd1556c459e19859d557e6ef2245ab7be2af8ae" },
                { "ne-NP", "7c4de0fa43510b49ba295241bfa3adf6232f32e57b3c2d2cbb62fd86dcc15c1d41a4fef3ea70b655a9e8122bf80010c8361d7a2eb4f2a84c14354016600a414e" },
                { "nl", "1afaaf3550b8ee734b8bb526f2052cb40304b0456464d4e2cd8e41195791f9a9abff46a8373399515fb5d50fa61630ea369caf2564506c7368643710081d8c0d" },
                { "nn-NO", "54443630186b07df87c56f9d87baa2f81da267a4cdc4a2c59107d789bfee7ab211970b2996ee852c7ea81ccf04955b8f6515caae5feda8fbc8a3bef3425278a5" },
                { "oc", "f6f2b50629bc65291a72d6f9395cfae709bc0cf54a129decb68d96cdaff49e770ee8cca8618c81ae5ba914152f5ce3d76a46d1c74b641bf0669cbd2f24aeea5b" },
                { "pa-IN", "71739b93d55abc4cada53c96e202ec82cc0e58b9dbcaf96405fb4db9cc833e3a228e9af1b64b8ddd522571c7e02bc99dce804a6a4c80ecc14e621309682d34e0" },
                { "pl", "987a93b442c5b35e02eebd0a9c47636628b72b30f2d50d579d79c321711156286d5735eba1e0fb90e5486c6469e2f9a4a844e358e104bffffd41fc161ae9ebbf" },
                { "pt-BR", "48d8f51d50903d9878ef8521c351733cfc7d09f3395069aa77bab56e06a293e4e53e859ca9c87dc1326cef9a4b4c54ee0e0c29ffb97a449fcfbb3cd2927ca69e" },
                { "pt-PT", "a6d13ceb1b5707bedfeb2454baf0cc234f68a9dc966128c0e35cf96e33d316f07ba4df0d2c8c0121c83f0cbba4b9846879a8be8b86e3c5f810dd7411381f072e" },
                { "rm", "d7ffcd139ca3fbc2caa293b0779c21534e7d1bcaabf8410376e32e9595a3da4a2b196977d6efc08cdd55ef5910eead993362ae66ccf4308cfff0d0781a0bb1be" },
                { "ro", "be6ad4e2cbc1160e79fd7f32419aab56541af18774fd2d9863a9a12a3c620af032a2d88597e9bfa375d2c631dbbcb0723b6d1a15ac208cc932d77fe8acbbf16a" },
                { "ru", "6e8eafaf3ee668bc9b24029a3a265fa2cbddc2261f0119cd7ba627b6e47a32a63c99a8f80fe2eab1d42f00df8597380275732117effb05127bd54355d2805015" },
                { "sat", "878d4dbe2cf50ea4a5886a92ce81fa94cd676252187508d6890e5dd1f005eb64cc947e3d9ce75570cd8c3907f0b341d37843983a84e05d59789a38dbc1a088be" },
                { "sc", "692d5b5a558784c244413ce20e162b957872dfe978a9856baf576badded58f94b925bd101385178c7be5a73ca58b0699a47e853c1282bb8478034168d489384e" },
                { "sco", "520ec27b7505323faa24c3fb9bf33e65f668a2365f236f796854ff41a72d3cfcfc37ca5928e3a287952e9c488df7603cf9da64c775c09613d304c596150e7139" },
                { "si", "dbe967581f1abcdba60680b0a4f19c3a4088f336dc85e77767155a9c97ebfb7631fa4e31a83a08b259d7f8bd66127af422957d8a0ff4fb6c1b2d8cd4f59fde6c" },
                { "sk", "09c47d3e24a968427e530a6bb0a9d75c73a7be285a6e580e18c767882fe46796c067acc22e04497103c3ef15875e9e4df0b5e3e346567a46d05121a99c2ad1f3" },
                { "skr", "e5f8345f94f61ce903b3cf9f1906e60f84db1a9d25b04d1302a753e8854327fcd871bcf04272095efb712096efe021cdf84fdaee4c47f40f812736b948ab05bb" },
                { "sl", "0d807b6079d746ba78e69773de84fb7a0ec8cadfce611435df7da2ff929d42ce66e69921e9e2dc9a5cba24c8a6308df6164419a7d8ba834a8d1893c801c7a1e9" },
                { "son", "a7197e3d1ba4264b73294a3abc958ac944af6dfc67040d98fc028af5e41ae1ba5a6a3bbd6cba05247c53276276921867d7f901618fb73cf964bc7420b447795a" },
                { "sq", "d9bd75211887624c779c8e31f70c84f459982699d24ac4ec9a833dc9e5680b0b52e541911d77624cb2a8f6eb83d36021125a24865e06921a9400e05aad95b22d" },
                { "sr", "bb0573d9c0743bf2ddd6d6448ae111b500fed0b41b83528028db0141e9fd0c099ab16a6d15d7ddce58e91f177828f45a7aec825ede8f28253445ab1bc77ddb41" },
                { "sv-SE", "7147783b5b606b3e70bba2916b4d3afe773946b22d3415d01d2ef92f6f99c7dd3500da87dd0d85eb43bb091aef6e83a1492aa1f6ba84364e5a5a3309d8901d50" },
                { "szl", "90b9a8e77b112d43237d3d232826c13bb2b8c867a46da4f44bca6bf6434b1855ac97d2233eee5f1eff8fd3cdf993fcdf8c7626ad8edec1e2ce9e78ff181261ba" },
                { "ta", "c6e1248b0767a32082f7d023bf83d02b1e3801c539068842e7e100279f41f538a476df04e29db75ce761f322a691066f12b03b72a90103d2e23cca5dc1eb440c" },
                { "te", "dc62fa15c132ef74ca8d899dc30c413311300ece70ce2765ee821b061f46fd34238f77cfc857b23b9f2ee2d9ea17ba9641b1696fdc4b0841f1511e9f6d90787e" },
                { "tg", "681f232143cd7ca11024e7bb5469b842c96f58185edc841799baf884cb914a3f2252c052ccd4d40e6ab863bac372035003b055207c189609812ef79386a817ea" },
                { "th", "256cfd5e4f65604dca47457c200c2e617730607389b5932962a0fc1a985eb39339ad42ae582ce4c5fe373c4744cbac62b3d6f80e13aade7c109fc95955346f61" },
                { "tl", "09968e91a6d7dfab2e178f417298306e659104f3e93e88dd627fd608d5b54a626149a16a28da0b9f1a802270d81dd5cfa138f6b0f19ab7d006a1faec393cd756" },
                { "tr", "24ddabf5ca914e63256c7f3cbd031c7734479cacdfbf3bc4960f1cbfc7e3ec3b1b389309501d01a0f76d752ab825da9232d2609d7e8dd76f36e4253f393f992c" },
                { "trs", "41932d00963c75f6cff156825c11d52cad36c068eaa1a19ab61e2ed40a12482cfc43e43aab9c84478efe822b227e3d94ca6d9e3c14c47a6e5d08b1644de83ce5" },
                { "uk", "09473a8da2fef1d076bdec15194e3c90327184dba182db6c7eeb964c6882da2dedb5bfd5bf7754a92008ac57454944db79fb87094816b6d6101c88e288166899" },
                { "ur", "6489e07dfcc6b1f14ea210dce2abac5b4f813f0959058a87839787316e64dd18deb49bec91890b97098117a125e42d44ce774b240fade67261324adf1faabcbb" },
                { "uz", "a6b9ca2fbc36f5f63cda29f85b5b7601d74dc4671d2345c947f94427e1a4d0436329384f9c4362f64c203fd208121b3529e950ad56916ecd4f3c4fadcca14650" },
                { "vi", "1a5d0545044be94c84fe3d06fd8d2a1814daa3583b6570b5ec9b6a1e6c97525cab6d10658811a7d17b098c275779c588b27a4e2b910d93986b375b618097c765" },
                { "xh", "82a2e4ba787fdf72d27188aca4c380d1674536a6238f49fdb304772b7e60c530184ed27de66501f4113457bb7ffa510bdbc399c4db98697ca9377c8ef013d744" },
                { "zh-CN", "c2acf7bde36a97e84528619bb1c765c2cfe19473e53086f69c3bc30735c8e0a41985cf9d6665126ebf56848c7be1e4bfe320343451b216f83f688d61edf050f2" },
                { "zh-TW", "68f1dbc45779a0865fdfee8feff280c69413479ec3ba1d31950cae31ef1b933e4b2949d889318f5820e15feec54a0d5493d6cc0933510fa7571d39ac3a4725cf" }
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
                return versions[^1].full();
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
