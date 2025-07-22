﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2025  Dirk Stolle

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
        private const string currentVersion = "142.0b1";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "0641449e1af60d63819b3cbbc03fabac5455e22334f3ae5cd91c59cb4aa964cdb6066c41112f8f936497118307f3223b6c6d43035fa9a7b651733aed00ac8f8b" },
                { "af", "c8495b1e7f4ce51a319a731a8a803972e94489a142cfd028092af494af5c8f2f38104b92c09fab94e125c857734149b0bf9a565809eb22b4d608a51938a15199" },
                { "an", "2a318a246e04fccee9c5b368f912159f4efd018e49cb082cb5ad9637d4e4ec1bb0732d8504dd7d05483d29bc336a01901a29d340b302b6dbe7d30e5296bbd50c" },
                { "ar", "52e4c3076328545daebb7d0c2a31aa7c14ac2f73b4e09ea7a9ef9ac606f07758a6f2342e6693e31e5a46e2214279102c744b342b65b9b2b4c36badab6df66e5d" },
                { "ast", "c44899c939d9b6dfcffe67c80068bd97c9bcdbd45e542dbda5044afef4be58b7552b679dc038c701bc85bf2d317c48bd6f42d2c786cb70f51ab374350beab83f" },
                { "az", "6ee252f546aa271bda3822fd76baa94e788d1a4c6770d0e000cf4c342d7073dd78fb8d35609805895a81ec9f68c3b1c19036f7632fdb1ff8dcf6656ac290ccd4" },
                { "be", "b33f3db3f939fdc9fdf909f99d7826f50ec538dc43e18f430fa047708170f428153fd7f6aabce4cf01f78c31d2da72217e4a3aa474f3f386ac58d993e55354ab" },
                { "bg", "392a10520313bfd06955e4b1b9032f5dbba1a506a7e17b82a8b1f902e5307ea5f548d21268b6563a67d66aa01a1ec9ef60d9e1df2e80716765ddefd248f72511" },
                { "bn", "dfc86d3e3b5a6681c613b2639b380a2677df1f2020403e9947c3f18f1621f43bdd6f2e0fe284083324631b831bdb070ab6608d6701e81b28fd30a1ae5cb63ef0" },
                { "br", "15ac7074b74bdd2af4b9dd008148b01a31796563e4678218f1d88c7a08a866e191db85585bf4bb858bcea5aa3ea6196b8a021915c02594c5a7cc0729025b3f4b" },
                { "bs", "0ee29f06699efc92594d6604ae062e97d28a99773bb20cc5475595beafcc29ed2507da66410ef1f3f472522d48466dd311c5159ba57527c143d67928d338945e" },
                { "ca", "e3e83f8362c748c9dadd071e5ef8fef4b8cb70046530cd9024ce9472576aaa9586b6fa014ef35b6efacfbb08e27ac0dd47254757c43c29689675a55eb1bca5a6" },
                { "cak", "30afa35652edafdc62f8ac9faba48e625fa489bc72dc62ba35d3b50c78c9e8b6f1d96c73ad0118581fcf46fc05eb78fe4e114f3f754672b4c5afacacf666b778" },
                { "cs", "a32d42483b97487763b20327b51a7bdf46f9e5668d1b95bc3801faba73971deae6b326882788b5cdbfff880c306398805a25f1bbee9a7ed68167e782d7936757" },
                { "cy", "90fd74be9d12869a5c97e8cc3bc06e571c2c523cebf8ad7d31c9f97fd596acd58d6a86c4abc80b89ef7cec8ece5ccd336177a2e72f1bf5c1e0ae3db48a7e5313" },
                { "da", "ff3249f607dbe839a081525428c9cde1fe2d1cc1ea32e514df71ec0d20d3413159450752006ca8e6ecbeeba10f2af93aaa09db95b7c4185aa28f7dd62f0f982b" },
                { "de", "54be02b7752a732a435eb450f0c3a5f418010093622b044375ce2e09da7b97bd53aa8d4dbe6d5b5a42bbebc04704cf278c9becba32a692a1fd841eb0e8651493" },
                { "dsb", "2f6604328224fad14f3703fdced600c7c3e603c1224884b76426b150aab6d0176249a0fd6dd6b6557400880ece59369acf2aedf8fd24476da6b67f6dbc1b81a6" },
                { "el", "983fff211855348fa50edf6d79186fb46ec1448066318df27dc0fc9c147891ff96bbaa43e55818d983d774f98d213994cdfbefd64d8a607228f3152bbfa98429" },
                { "en-CA", "f2512c87a9e5f994f9f02cd441d352da16871098ea3a72430f3636bd3a0b69dc7788b3f8da8a43fda6f45e6f89ed3de67f4b42c4eb94cea7ee2bd8c7ed46d69a" },
                { "en-GB", "a57a40943e5c52c03227dc0abec1a7156562c0953b935a9b81a119bfacd6d8ff27800a363fd99ca27566329bf34df40a301184da0fb8db2dd9c11cb52823f0f5" },
                { "en-US", "ab2c40051b480ca2638a756d87851c54769bb8cda455aa24be5e18b8344a8f3f166e84231e06db03d5bab196be5fc55ef0c1b7aaa01019d12c8fa0cc8e974406" },
                { "eo", "c391457ee9cccd14957ee8df378db1b44879d244a5c59fa788b43b5d09d4861b4046373fe19a58e785d3ebadf59c222f4b9ef4f13df6ea8f6695bedbfe83ea51" },
                { "es-AR", "b5f301777df7a65155eef146c8f5d42e63591e8ff41bb079c3665b3375a859f5bcf10f3e62b8b4ba4bf470e6975e4062f8df499050a3d8e5bea12beff55ab4e9" },
                { "es-CL", "787dcdee12d3145322eb575f61bd4dc3eb8065e468f75600f904dd45be32290a09473effd1e5cde18b921a6e8855c55276126c7a99d6be7f5fffc565a22a8bb6" },
                { "es-ES", "5bdd37fc5cd7cb40ca6f9c713ad75c6c3d11b1e1c04a694397ec8aee81bffea76023dd8b5e474871188914df0b92542ba59e61b5922ef7fe509d42b4e0b91138" },
                { "es-MX", "4d17c9f286d9173c996cf5e72722c9e3300745e92a33f39724ff37c3eff86a9a52034a5feaf63ac661db8523f05d7a96ea0f672deb808c10e8147b0cf0089c5f" },
                { "et", "c1bd088f5032220d6b3c9deaa9b1521e23f787028cfba49d1716a8885cb970b8caad917641bf9da4a8be74a1811c8fd77333c3762b250dd8b2f4fbcef7b31ff3" },
                { "eu", "93517d7985ccf8145fde478d4c5dbf35de25e40fed8f13c21fa0c131f27bcb0d6e41a90f6277daac5ef39820eb42959b6702b3cf977baf981e5e13653ad14cb5" },
                { "fa", "b9d96ba0a853f8225768acdea76a0703ac910459340188c77fed87b575c2cfdaba203ee6c23fd2205ec36ada1b0ef44dc8c5958efa11a065aa8f6b9ccef41f8c" },
                { "ff", "2aea4a81f002f1a5d49c4cc559b650f2ade232971485a5b744391f8144804cd0fa9dd1dc5ee8bc6abf13cb0a817bf080293c076dbb550440c2d67ccb67a3b3a1" },
                { "fi", "77092369f994c8a7f3e4b4a7dfd9bca23584dd9dc8cc3a28f02e7f830604ac5ce0c3fc9be39440f59726b4bdd2c7112fe3997d44929e9b7a8767fa29e87fad4a" },
                { "fr", "76b042561d9eb41cae2e03b9b588a8b6d77258f540d76ed7c1b79229e08f8dd944adb49b02709c46e837bc0ccd414eefd725ebca4745c7570947756387da67c2" },
                { "fur", "72eb084c4562bab96c50f29b524a3f6ca6f8efdee047d832b80bb892aca0ab43828bacdae17b342de0751abd150d5be211b4caeffb37926131c08027a0c4e85a" },
                { "fy-NL", "1866cfa16d64d920428bb3236385e1070b7c480dc58d99e2a7b10f98141eac7753b52ffb5ddcead93574219db542d2897cd184861d52926ce431952c00e3d8d2" },
                { "ga-IE", "bb958081d41b961bbb5151a0cb6cce39271661472cde0e2cf5332d39851351544490af921917f84b456fc06a006ffb7697cc95646029b1a328171b137b4c55b9" },
                { "gd", "290d1da337d590b3aabfdb75d4b82f35cb138ca795678cf587b0d77ada9466e7924e1658e4fcd469f5c23be22db1544a29ba392bd6c1824a6cfb33d4dd202ed1" },
                { "gl", "1532cdc309390fc2844bf5a9c24564bd7aca283d290ee7a5144d022735a2ed101818f0fbd58d607418939adee6694ba8c9d46b64f800ddb38588921b14a728ef" },
                { "gn", "370c101b37d8d306cc709d58ba4a85a3d9c69e87fa4e50e2cf1a17824841241f35a10cea07029b713b081ebde57bf472d351a725b0c63170dfdafcd2751a72c7" },
                { "gu-IN", "595517d474283cf4ad37a9d71359f2716ebd63c4ff54b7ff2b0e5ddf5d73c4bc055317b2c03f0e0e905b69514137e32fe6a6426d899921504f4071abbc2355cc" },
                { "he", "767b6c6edec48a5b06203a909b0725008bf23f1ca3a5b4b07d4e41e0e6ee636b8ab6ad5a219ea56512db5942c9242054a21acfabe41be87351470e261a09be60" },
                { "hi-IN", "79f5ff319a6d3df3d5fe961f0e52e0cd23d904ba34ce4547d66d636b6f56a70cdaa01bbb84484270fcb1ae6d366457cb67b826baf1a8972a638090f277423218" },
                { "hr", "ea3109d99491af5095812f926e387f75d045518c06671cfb91abf01f2c1860640b161c4731975a87dcd54cbef98c60de439dff47dcfde740861fb5f33b543489" },
                { "hsb", "8aa79945da5be5df925e604d40aa95a993ed0ccb0854f41557674aec6c58032185ed79a608a73e55a615801d46e82efcbf4a1ee80fef074ce873130f3fb97c6c" },
                { "hu", "99abf00f8918120bdb24a0eff270fa1923dc71b7367918de69ab3690f646d60a9875956b10b9bdfba36c9a5b1ce3057334a4c49854f0babc6c2d0603ef844d46" },
                { "hy-AM", "caefb6f5fbefd6afcf5ab43f1c6c83b1cb6d1fb2905acc978511c6b71ccad551bfc0a7b860ce40fe95e70d746f7d455f1d4165a670e2a50b1718fb2afc21a224" },
                { "ia", "02e839e1302784168e2c635effe2a1905eba46f9b53d40618da095d39e444ab9321b49ea68db6a63f61d4538ea124728d026fad122c69a2d81129767af64d336" },
                { "id", "0801667082a0198166e10e6d639f9f1db46b0cf12f3314a851b2cf958f1d5e5fc6c199e6167ac2c3bfc3cf540adaad59f4c9475906ee38a09f427419363cdb5d" },
                { "is", "c327fbd4564f66c6003147016e056620712f5ca0bcf72f9e96ac03297a8937ce3fb9b97abe894f09faa24dd15570f32a0afb01464b21879eeced57b15e1aace4" },
                { "it", "5d0fd3e695019607fda63458eaadbaaeda4603ca5a5bfaa0af80bd1167720f57bbc896b02611750c50b333aafb13a5404b8305d395a37d0c1e5f1a0be8108a01" },
                { "ja", "70c4ab0d4a4c27f6f9fced3f35d68bacee9bd9e5877c5f224fb8a7b5aa2c793f6401957fd33690ae7cf54416c4ae330f860a5b6688fa1cb5b0dd87971b8f8104" },
                { "ka", "66af57dcc14821eb6839254d190a6c9d40651e327643535462a0c84f1283c5af0f48a3667a530b7f78fe96c6def4a6943d89ecaf894fac511cc3e49923f149de" },
                { "kab", "0cf8f36c8ae86a24f4bddf9c66b54db27fc67b4227020800178b3543f3150d6f905785d6d4db940c7f17a213de25ab4b024e9e0a9dfe362cc426b752c230bf23" },
                { "kk", "a54ecbce5c0d58d93b819715a9d3088e571d1110051a762bfa03030e7beef71486e02f3b5d9ea0bb88cb82820f50729bbea3dfe8056fb041ce93606be915c316" },
                { "km", "62ee0fba4f4541330dfc5b1793702db7e6a3a66dc63fd2d0f12de9badaa605d2f81514364517c912613cf6e3debf92486799eede6e072b54ca8f7fb8320a8787" },
                { "kn", "771e24efa1d19e82ffb232779d42ffb44fca6c256ee8e29de67ec8667cace90f4121145f13f7671adfe8283b2baa52926ec220a039cb500b057285254ac62ced" },
                { "ko", "71ef892c11eb363500168db19805213e8fb439805ba45cc365241a791ce4f67086498f2b56560d0fcd10d713d49f787f1bb488e12367fb41558e2134cad45462" },
                { "lij", "e35dcfce188631c609bf754e3aa5b25e77d5f0cd633ed5586b4226345443ba0e4ef12325997ca890d567be7df0476e68e0dd3d1abf1f899ee2554e08541a53b6" },
                { "lt", "1c583f02a6ef6f185c1c10e723cea8d94a1bcd78d2c36a4a668f043714bd3385007f49cbc37baae317496c401c0f649b38eb4ef412b368b5e9235611f86ee08d" },
                { "lv", "4f5e047bd87808967027a0583b08db453d1672e480f8ecc252d48fa54f32871868931cf997f111641d2fe7898eb41485d7d00f37c5903b8310a0645f17e94a8a" },
                { "mk", "4656d730693c4d90008c8e2aa45949c6e30adb4f5a8834e7ae31fa6ee82d8bb59da66fe4568f7571b5c1de55edd2a4d8e53e51c89fc65a5bb6ae463712bfc5b2" },
                { "mr", "fd681e8b40440920a48e28cdd242f961589e423d9aef849fb978f861c625932b5cc6cf7c1909dcabc2579945d8ac0fb17fae0fdeedc04863e189bea8ac405436" },
                { "ms", "b2648e65b9cba9530c3e43892473ea5def12847cf1aa06b017bbc1ff6c29c31f900bc65da2b8378faf716d6d4603205e31e3064157af05075b0976e1aa855e09" },
                { "my", "5a5b05e60b37545ffc862dde36f8b2aef1338e0f83ae0bd02454336f054ccdf359f8f519cae9da6e675b93063ea879d451c433e77a0bc4540d20d68886b56335" },
                { "nb-NO", "16e9484e8a51d8a278a2ef733778dbf4ed3967f532047811496c327aed5c7729d62f213c2018fdb04b0154a0e336ce6a5d5df931c1f556edec46d25c32556b93" },
                { "ne-NP", "3dcf960ddc297b3a954e0c18e1f01af77ffbbac81a8cb929a55cbd0ebb84b2aa9aa70aec0d4bef49d22b9519f6fafbdf13003f5e0148c5e55a3d0a5ee16febd5" },
                { "nl", "ce784d3aebc1d9ac0f3e407ba8f699a29779306cdd4a1c768c5e9551301113bb8df8ab51c7cb4ee3cfdad6bc8163aeffad183f8aa1ef67e5ba915356ab723e76" },
                { "nn-NO", "4971a1764ade21aa49f2d9d2ad99cbd492688cfa95be60d6eba819de96f8518f52c09a4256704847b2c797b818de752bf66478d07b9efcf2d25088577616b01a" },
                { "oc", "ff5d07b884d7502c01681c2f102b4b5ac95fe095ce8e25eac11717899471afc25eda6aad3266175e9b795e6347dcbd732a7873369e66beaebdada6013f95aa98" },
                { "pa-IN", "24d1c879a71d6d467224d58e1f3ba7a269bbd0dedfec5e8247f2378e3038fdb8614c7e62f303572d624b07abf5913d9d546e20c892fb4d3d7efcb011bb5e6c16" },
                { "pl", "5208d50f119a4fa998eec1c693ba39aca0a8f4374446a9f118e710f8b8a63163d868c10f0fda136fc08e49c0d10621efec1b05ea87c2544dc3029962534638ed" },
                { "pt-BR", "d94a09b662a23ca2999b604017a2683fd70d95aa28036d3ac8c88412d72a7deccfc0265b9f91e21f6b71121cc3cc0685c633b3e64fa792f92ea5db5b09feca69" },
                { "pt-PT", "4828198b1b2c0935d809b2a40cfa942de706fc3bddcdace66df0d61bbcb4c341b4a4d784830e697f8e5c96f3bcfb514de46e65c025c70fb885944031db5b0d3c" },
                { "rm", "efef95b2a12fef2308e33533400aafa8487e2c2a8ccdc38f0695311384ded2286757e22a9a83dadeb76adf1b1c3f3505da772ffb6dfc9a5487dab811d9984b8f" },
                { "ro", "c2b50d7809078fd5c196156c8670ba16274d4d485cb86fad715792fa2da23034b4303ebf3281de302642a669374e30b63ec6e86a5878dbdb42277c584d963a2c" },
                { "ru", "e43bea1ce989ab219f74b8c1c097c552e30ac400993e0e9178a968e6b4ec62a985d59bcbcfb3e590f0021303a4fffc9ea2ff12cadfa003999a40ce7c1165ddcd" },
                { "sat", "d6aba2cf26fc81d6b32e2dce619d284c2a39905bb1f6720ca07a66434a7473e561c91238866314f4f7a1cc2dfac443e390fcfd07a8ecb7ff1c0e95e760bef82b" },
                { "sc", "ab0cbe2098c924c1beef0983620b6d4aea2b49c203b24b4bbf2865a33c63a348f2862895fc5004124e5785bf7121a226514b02608ba14fcb0d896d7493d638b3" },
                { "sco", "296f5a13d40721342d4a8c23c6b10c211b8ad2763599f89abc0693268359b671eb9506115afde60c9cb37ec8263cb9423dd60f9d5f279827a16cccd596123e90" },
                { "si", "51b4ab630b3fb74cbbc4756f57d7006d45730a19d092a7dab8377b07f411dde534ceffe3cd76b9c36c0c640a149ce3740fbd3e5cafa420ce00ee6da8c19b251b" },
                { "sk", "15ba6902054f350c8c6c30cde231295d0e35e60d1dafd5ec0c593e38b0fd7fa671765b10ac8710015097047a70b9fe52711413f2482cbde9f8f466f4eee39e20" },
                { "skr", "6349e00429579c151407ef4555c304367d50e92d1909632a5660e287daf634cfb4c17815d8cd5c8ec6d1d21d40ade36f4dca2ed43f554b7bf402b94f22aefa9c" },
                { "sl", "37a50dd74cdb2aa123d48e1ae4d01f4ce22f5f6f91cfc1f54c1d9121bb7fa0e4aeaa32a5feb959a5ea247a1ce436df736d02fef1d79ab551d31033ded7f7b966" },
                { "son", "47f881c1e61502e7b0edd1a2791aebd7fa65e92f40f0da92b07fefd3165981b6c69f2a198ceffcefd1d6bd4f90e65269141a7c8d6623c30ac2caa9c294ea6df5" },
                { "sq", "ba284fab374f6efbda3cd0f36cd844f2714a80ff1681c11374d4d7c158f0a2852829d6e2a9f46a42626e6127dc59c69d21de67f3d335f7252b39f45cf3b7ad66" },
                { "sr", "a16b035a1c45bea350fce21432d8b5cc7054ebcb9278da3b124fc91fa9dfadf7f87d8c58976f2bf78de961919a50c5e5985432c0a9eea033479ff7cd63034bff" },
                { "sv-SE", "325f0ebe2155d81da1c0fc0325091928c572ced80d8b42471b6f8112c62966fa44d2c95d3d4a847c9992000caa94d4dad58a3ef2916c9fd0ce0c301b98f7f5f1" },
                { "szl", "090304b121840851aaf6886219e581a56c81cbce60f7207e9dc2cd1195a4af71b84d0ebc4fc9813a628ff325e25b30a53bb0ad81ca943a258e23f825b7fc22ad" },
                { "ta", "e6ad244bf8838b8c5a124b16ec5c4509adf0d259cbbb8ae586d4e92aef6053900ea53a8244f20e41cef2c4c8db8f21b1d35ddcf0a238bb87853bf159eb502060" },
                { "te", "b69c316dd6114bb9256f40feb810beaaadb75db9361279129c556b4f120a231478316aca693dd0742f37c67e5c3a6f539c9470ab38f12e60b7d6ed86ecf26d70" },
                { "tg", "d0f2217aefe51866b120f0d4afb5f58ef7a63c480e5cf3c2745e01243c9b7b6a8b7be94d76a119e0ad4747798d045d032754106baf438d9d727b1f9ba75a5d17" },
                { "th", "b44b4a8303656c2e2ff980805179525cd36584b2b6bb2de999a200e2c9a2de1be720b0af291eff50fb0a17d3359d2e41f6699589ebfc1f326407d0c189bef4c8" },
                { "tl", "f0c3f7e50bf4b74d1aed4e2ae411e39056059df75ec910eebe565944575187433fbd7fa8b97b255a58c4662faf8720f0b437ea2c9dc329e875955d78c61d19f0" },
                { "tr", "9f1a0c2f9a2a2c87e0e262078dd25b6ee559ff7808e2261afe5224f9971562fd8564824f9657bed116190ba00fcaae9c5a7a4630788c5d5885b860beb9dc7c4a" },
                { "trs", "c30316c5de30c37463fce5280d516eeeb762c49cea07d50565c0ce49cc3545bd1f529d7f7f9e56c2e81bf39610582b49c472043087d188fab5fc4457c87a5459" },
                { "uk", "0f24e6d925e4253f12c51a118e5d895c6fd929dcbbe921f46d23f6089cb5a1e405112bdc2cc5b010643e375d04884673292c4b3a0b76e1f95041d78a8c8d9a77" },
                { "ur", "0055e36970e537cfd321eca3b0d2d67ba6605c4eaf5b1651258e7a222bd49cb96bff6bc16f868400856064f3f574d44dbabf97b99682ae58f61fc819bfc955b7" },
                { "uz", "439d667da5e4d35c9c65d88ac8285e38d66c31a857db32fd0181bfe1750904d031a5cc08f841c7f9ad51cd30272c0f934ea0f6b6733abde483cf1eae6767d9c2" },
                { "vi", "524c02986442a5107556a4733ead1f7323a91b5b68be54ca22013d9a72c564ca7086cb2b197ed5be4a9e9cdb7d165baf1c37ba0cb549197434dbd8230037565b" },
                { "xh", "e37a1e36b996995c736419235d36497f2e4bc1d431bcd8e45de863770b6d5ec66a63ce878f1291812e6cdf15303e72aba9b4d25f034734404999897be8daa267" },
                { "zh-CN", "a14a1032a2ed3c3073e2c3148b6afa989c96af337fd78042f741a72e6dbd4cbcc7d485119c3b833ae207351f06f487648c6d7ac144114cfe50ba6e90ae882dce" },
                { "zh-TW", "d1a4e745cc52fae59a466d14d3876c213d2d1f09e90f46a3f12abe81902fa6363afe539966d253595ace194503b29ee32d908c8d7fb81f6e281aae0411514cfb" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "2cc81faa5546f7660c5fec87f46ceb7fdbac3bb6f59d2772ac40ee8d347f9adf0dc99a8401b7e02e87d9ee6c709fe8efaaedfa1bf55d495a6a14108876de4290" },
                { "af", "4e66a45da53f64f79ba4ce0cb2f13dee89317ddd67e24b2a6422c6da729c3cdf6f29f8c4ae1d94ac98978dcd4e9edb70e26b7b578a0c959143ea331f27a200c3" },
                { "an", "b464b0d16ae52fa3144d294343e858d9389960c54484095b3f996953c883f1b6adac2237023b533ad83025a8b89a11786ea68d3abfc5cf964c3073d7f4671d2e" },
                { "ar", "976b30672130a9a191f92b6d6779427988c09fce66eab392265b32ae7479bca5431f716dee1df01325efde2a52dec81096083c38535afd5669d5a5b34c45e87a" },
                { "ast", "926957bab98809d51ee17b79310f282d40314e5c72accfd31556ba57ea4da52a578a13ba7d493e36429ae90dca3f9bd324329c52c2f05809d52d46d4137f2bfd" },
                { "az", "d1e861ee8d881e03836705c3559cc18956ec82e8f5ce2d6be1e4b02d9410e7ca888ea0235b02fafe8e60f2d23b895b392f7fc02bd0c938860c8f6eb3b81347d2" },
                { "be", "a0e67947ca92e5d6994d3448c963b5e18392c7cc3023a4ba893dd30ba18f9c93de56535053a3644ecd93635ca2cc1e5e09c26524821fa1efc18582c97da5fcab" },
                { "bg", "e448c5c5f26e5540d7dcc7d06540fa0f5fe0d814db9e3a1c3fb98941a1de14725d88e1fafd4759af6b760d022e18057f1fb7db323e1967d12a76fe6302ec1e27" },
                { "bn", "8676d86a31586428896dac64e6bf628947a75f9977352201f36abb521e73d1f778a5198ffbed8a177b2caeca6bf960ef50de0a55a4a6288e790f1459a57f2e55" },
                { "br", "cd2a3bac420df7e0819433757a64e862ed80426b0ec5e255e1881483ee307e6507c321bb682526179472c00b0157f52ea0d9edd553b3e9f9fa6a741a8a1e9a2e" },
                { "bs", "c1da196c942abdbfc277acf6de6c6f520de841808a2e705e7e45d9fe2d8895298c98c9a2d75d69c8b19f80297bc88c6e6f7c562c751ff4172c21663404fb01aa" },
                { "ca", "2531f24a89462c25002441c3da290b69889d818313dbeb0ebef25520eb9e756634d7385d5ad323bbbe77e5c3e244e00369acfbc76f8b3c23788f0e954b368b05" },
                { "cak", "6426dfcc132d3e75657fcdd5e19cd6fe642333ae394194f96ba9975c418fda91b54e78246a46a71d4aa4e1a08c44231c1e2dadbc7d5158fe3c455e5226770c27" },
                { "cs", "56d13faf413ec2803dab84292c1aeb801b046d98d606d91a0c582182a70ed331546d832c1e65dd705c5f2e1a543aa946c1a36201c2b89f896b6118841ef82f3d" },
                { "cy", "673caaadb61c560abe6c45ae9ddf93b2c3bc17f0d1d6946e5304eee33e670bf2f98a157dcbf0ee25b68c7076ac361319dba4bd136ab08da8e7c32ae0386cc9cf" },
                { "da", "c9797fa11e408ef45a97ab4cfa534bb5686c68f8e3822ff4053a87636d63ada77c114aa9cd2a38e7b8985c6bff6520139511f789be52860be958ee9be0eb3837" },
                { "de", "362880a32a2dd96505f59216db650a8391bbdbea2461205e26fea2b8caa28739620a8be1013f19ccfc1d26a5febd6d51806661939735e35bfbdca9ace0acc35a" },
                { "dsb", "eddaa5c12d2d3adbe146825a7b34bf0356f4bf9fad724ebd95eaf2b18b42e8f1b900c24120ed4585fab7e41fb0ca21d9ee11465fce4c0298ba15620d5fd7e596" },
                { "el", "000344960356b02e96bc5c4b354faba3d4e479b79094408a8a947067dc4077d6b3982cde8098b6efc16cc0d20be23ef4ccb82b360de92ad15c2d5d2ba51cfca5" },
                { "en-CA", "b56c74dd645cfea6d124436866b6194d053578348766996ad47e5bd95a00a7ae20e53fe4e769d093f87ae8c8a9484976a12cf77392766abb7fb559c8a8b2e855" },
                { "en-GB", "2c442e597760530eeafd0d4f73a1a36bbaad3e98b9a9fd2009b1f80182a4887a8df0000f1956ee5d8743bc027e566b612c1b602dda98c16585130d2a29cfb266" },
                { "en-US", "321e8a574a2d9180371151abdc03de49a008e288f8b3710e87ea753a8a5d23f53ff10e8222efe5db5c4010b2b822de9a9c69450c4d8127bed434e55aa75dfc8e" },
                { "eo", "1c629b0522ee2593fc98f9ed9b2fbec24efce0ea15fb7c9d87070cc45a44f53dcbee4b46a88d0723e92e27fb92a55e758baf83318807e81296ff51115602def1" },
                { "es-AR", "83ef40637ee22de23ca1220f38008da8070073982a793cb079ae834e25311e74526da8da0c72a6c9729d6a9b41ecd6a71822bc37fe881a7d1562c0db8e689382" },
                { "es-CL", "de1d4c4392079260a1c88a263d403efd03875e0433a6d95249c101ea83f45e46f1e7b6e6eafbe7de4e28fede99f594989e225150f89c9bb5975ebedc27be4115" },
                { "es-ES", "93899545f446b388c3b966c3b5ae1c5f5efea2c58ef1aa1cae9e00688c4cd0217b9c831e2b6e6e7127221f7d0c387ec10fd42c724b63f0cabad080ff72efb4b7" },
                { "es-MX", "6c85af90a7b159c8d42bec26a365fcb6c1469aa25a848be2a7026b60945c24358c15ebbd7b073675abc3148204ac86ba1cddeecdc3ae9bd2ed0fa580f4d96f33" },
                { "et", "2ff77c36df5da87e6dfe50576175d4b2ad95fc256c45318bc2f71bbc4bb35e20ad7f263982b8aa6a5da37769ff82cb80e7f49f13f23e19405c8ef50c6d447b3f" },
                { "eu", "69468b4432e5dbe092bd9e3d6dd65be9eb0be60f82540b3790d2d1b8843bf2606deea6cb016f16dee3447c754ade5b6b8aacb73723704f92a734eb396c3600a9" },
                { "fa", "a61018e74b34ccf2cebe08dd599f51846554e23d95b0fa411c979c3c441b1a516e28345ff1f509176be5b597ecdb90396b28da9afa4ac4dcdc31f9cf515bae5c" },
                { "ff", "636758eb8a708d4b3c0612acb0c329ea9f3173e3a2bc033bc0a8bbe1ed9ab124e76f583b3389cfb765e9efb3d2b3dd78c687921d5f5aeff085ef7e40a80f5b14" },
                { "fi", "c5480284b1c3b4111061fbb3e557f6aab1c9c61547f51c24dee7b98314a05e43d46526fb43f448bd9fbb0060b844c10e8777fdecb74759056c5bed1ff9fc4cf8" },
                { "fr", "018e452dcc85105eff8d588918dbf3d54496c35134b5ebdae39a1bf0842a5e593c008a85d47a7e1c1e1df8ee97969de9f7a18b6dbe3523740565f647ca9ad9c4" },
                { "fur", "f42da6d476b86955f641fd31bcc2d5c4f42bdc15d9a081304577f81aeaf6efdaf15de4d4a9836896249f61ee37a6a16b72dd98e2b71796dbce1bc90a7b473163" },
                { "fy-NL", "0fe2135370d457bc9a48a4da81956965b0fe87da0c7c015b817cd6bfdff786c423049311cd9d288d727a1faf4bd821fd365705da3b3cc80a497cacb4d848f17f" },
                { "ga-IE", "920b08d1d80564bed106f6aedbed02c13a8559f9dbe28cca9c672e2f573fd77c147ec3cea2f6f82ad12dbf3feadc157daecf37e0be2cae067ec8d250c997793a" },
                { "gd", "4f4f2a17735e54219792af1d6ccfc014d60dabe52bb2cfa5208aaceff47225e1ce0835cac793a93f5b952aaa51ae61b2ed9f42d6eb4d6316b943f667c80fb545" },
                { "gl", "40e6819e015e237bca2fc4d5dfce1571533aa11573afe3222112d0372715294ad3f88145a7a5d923070ea7aa87108be81cb4082e1b2fdc33973c4350889c14b6" },
                { "gn", "20911d910c3623c6e7fb9c5d92a092ad4991d38b7dd4b3adc83a4e93856914e3f89307828b9454291af0e4e71954cf9ccd9956787b05984b30ba0f14768f2bc9" },
                { "gu-IN", "d7eba6b60d0cc73e7b1f68400093b5a58c9e4149a7530af9448a3cafbf1f06d8d41d540b14d475536d82f2e5493f1888d73035a191469b489857fcddea990aa7" },
                { "he", "ec61dba6a961fb4a0610608f45ab2b23389d772e2f471b3c656efc1f34945dd6292e0176e5ed6d8deaf1c66a5d3ab8e8cfbeb4ba39e2406ad8d858c095f4b3e3" },
                { "hi-IN", "a40cc0240ad55cccb01dcd71aae154cff09e8aebf86484b38da48bb533e2e3d9c3b05a0606d9065b27624b60b4862250f03e612dc17844b98cc3a91ea74d608f" },
                { "hr", "1d9fefc8594185f427f508f9e1b881a7ba92d9ccb8aa996adc7f3b1bb8762af2b12267ab30b65e83c824bdaf2fe14f92f99500025c1c043e5122df363c92b5a7" },
                { "hsb", "6b08321b4129827dca4be259a4b34843b1995401e643fabc39cdb6a8a860e61e85d59fb209f4e48b19907f3f133bb777abc2b6481d1967547f9db2fefb441fbc" },
                { "hu", "bfff03d641bb1edfc02149503bd8d776f7afe69e1fe16ae74694837e39679a4fdc874ceea242567c716a6380e12cb5a5c62cc2112366b46a797ee50e46861c1f" },
                { "hy-AM", "8b59b0062d00f325d4044014622eba6799e72f949c4c72ac016ab8a25a5a1e5e249c670f31154bcfcdeaebbba93fa8cc38ffe285cc631bd28e9f112be2c2750e" },
                { "ia", "584fb4093c69eb90b3ba9c6539d77609fd41158b8df18c76d86ba458bee5e75de72a797d49c8e7d76c770072232c33fa6ceaf02e135327d1c4274e9275a2342b" },
                { "id", "9d71baa7098af6535827dfb6ff9acd7c1b03b4c51906969004008ea352afb1c565a8dcdebb7430b1e6ba695af7da8fac29e680290b9eb02fb8f9dede9b8555e2" },
                { "is", "0c2957d6165dc42fab2fb5216d80c98c9c115831b10e60ef1d47900927b4bc2ee3954b7205c967d12887b2c4d331b1c5eeb7702975eba873e215ee02fca9bbdd" },
                { "it", "227e5974a8375fbd9b89c7689bf5491e0577f91a1f6347fd6c09075191611fc14ca7195d6bd4fd97b6e3364348e116345bd8cc75bcf2f9a18e05c74f6cc8e567" },
                { "ja", "89d8af0494d9a561ca4432a56392ebabe4d908f7a34de166706ba679acd0097d0e0597b30860cfdb13040e171d3b332218db190f920e320368479beac880f420" },
                { "ka", "d42564cdf3ba6d9f46cb5ccb5eb137386b3b3b0df339064e2a268b5393d7fe45f9a84d316f76f9cb649cdfea28caf175737ff050443d0b9dacfa6d7d40f5e803" },
                { "kab", "98ca67a54ff65f3d58dcb8261df7bb38fdc3279e58479eb75242bec6d499edef9422da62963199ed71f901710b449f6b34d14d274bd6f78dfc7c0d69c25f0b2d" },
                { "kk", "38710fa73a62122538e7619b67afed1b3174775ee020f3317a61e6d53abcfb6536d01029e7fc5e2a49f106ecf8922aa7bbfcf11cb17d578b740f2870d7875cc4" },
                { "km", "6289cbaac36417df67a612025c61a0470e72ea3f9ac968821c95cf059775f802cfbd4cd7dad05fd623f73438bd00c0d5167f0897bf3f0028fe740eac96246542" },
                { "kn", "577c227bc1af0a5deba06c22973990dc774a21b8c9e3f004965cab6ff21413a4a1fd26db92495aeb9648e36a5adbc9a8398cc7e7384b9fe09d4c7656025d7bd8" },
                { "ko", "c5cbc3446c377b5029ffad355e51b88c4b9399c01be9101fda2b64f043a3eb05c696f610ce68f72ebee7dcbdbe4df4ae42a199a3fc1abfc12252f13da05fd812" },
                { "lij", "39e7df824f04c414eeb02ba491f15074a6188f37d5a967aed39b2a5259c1d65f3746736ba2e39c2177067ea2e57a84695d32937959ec42ee1968405ecebd60ae" },
                { "lt", "3605f0d5f8894272a5d06cce081468d274bab814907d8475dfc4fa63dae71f57ec677086fca6ced973f99e221ebebbbc38aae8bc378f7e5b281336ec98806310" },
                { "lv", "5c7d794d6dbc1721f82f496afe52047649ae0d46b8e3c29dd9bcaf1209fd531a9d6aa238b40a6f5767498cf5ec144dd708628b6ba7f741db08dd3a9e70d761bf" },
                { "mk", "caa50a361d86050ca726f5f726e3b0fc8ae2cfbcd57fbac2d5258278df77149277a7cd3e36837d345d69492269afe9afeec3633b154ef1d3489ab118ec93dc77" },
                { "mr", "5bd352c3c9777a71bfe79f569d3784b2739959847e46165ef3f89b0914ededaa051b982024e67679b310e06e105d167e9ab0d5cb6f683687069039247ea7143e" },
                { "ms", "528e08483744ab355dfa4fc5010c01a0d706208c5a6551ead98afe91c6dac0075e6d78981fdbd4dccefc5b7682de38bd515d69c7ed45c82f9518106c836dacdd" },
                { "my", "77b370d6b859391b9ba28c19271aec7cb1e9518248a5442b3cb41f1bc3b04d1202d2d7c0b2ce704e0b56f121c936f501db14d145861a22c67991c0ed90cc100b" },
                { "nb-NO", "ec1f1e2b2456abc0dae8556f379534fb08db9515cd8c189e3c24bba47e8c71424c7b504d70ca8bc07e2ae9133cdbf36f3434bb6b4aee876d8c7d9ea1411b8830" },
                { "ne-NP", "247d78e57d0382905d23d14f8cfd9fd3616f07a04f5f831c574bc117394e1d167391930a04bbfbe266530f822461c86d467d1791a17da30c6c8f5b8a21dbd19a" },
                { "nl", "08c3c2852fd56b45eb71625978ccd0db31a0dcad6db0fa4e844a819c4178377152057e26a13588e6bec5c2ac43ef5dfdf56b3c8c63af03b8ce19682bcfb590ed" },
                { "nn-NO", "4c0c70e775099d12eb18ae09b1520dd044e8da2a2ca33ae384752bb4a79e98b5eaac78d2f8cebd6ca93bd000baa477a42b9739ff5c3614d42393fc5be64adc6e" },
                { "oc", "15e0967a43d3460afae24f7dd30b0fb2e2c0bf806abf74a9321f4bf6dc0adba2ff50e0aa62a020b0880d03d008e2a3f1c22effb481387647802d9932dac61abf" },
                { "pa-IN", "22a33cf5c9a475524da8dfa1f716cb56961056e5cca21bfc1de60879a7ac516d8bebd42f0cf50be14769e0891ca2b3a8d466cfcd8e31a655b7274c51dba4b09e" },
                { "pl", "3722333de1d982d18992b4bc665a4371db8d2ab52a9714a9a5667a19340a612ea19796782880e22f72a01dc8ab1888692db6c27c7f22f1a8bbbe44e035e5f676" },
                { "pt-BR", "986f0f80479f71d1b563d32b54680720f32f2d1a7e91b25bdcacf34e8fd11477c79840b6887ab5efc71e35c1cb2cacc470347ff270c04f808bd8e8086ac970a7" },
                { "pt-PT", "246b43e05a696dec1a2c1749f8bb88c78f643b783fa41b4a44c5686c2c2f8c16fe7fcd1d358dc8820df32ce26b7756764770b9b497bb964f8b6d947eecabf5e6" },
                { "rm", "15c143410a15571a3329f414e491eebbb6bb8f0cfeefa685b416bd36d2b61de6cf0642225b7923ab6f9bc7496b052440a70a31ecdaaaad1b89c05b00987ce3b8" },
                { "ro", "cd5f5c1c969fcac58221e89bc641c9648886f8645046f729b6c84991dbd2383a62d94c32316a80441fb92dbc23a5d9547089e01e02382c68457ce9cd4af67801" },
                { "ru", "d7e68e957a0faa5aaf28a3372a63025bd1e41160cfb5f3b6ba041225459597ac89c866e04b65723660f8268b547d438780c92547a4051be9c3d060baa6c08115" },
                { "sat", "d7a7fcd043399aee2efbda83b76b7f28532539059e33cccd0dacfa690e1ce345aad2cd587fb30a832f85c3bc3b843972a3f43be592bfaa82a9da4e85bd699cd6" },
                { "sc", "a413b62c20bfb0bf2d9d2792c82a23efafadee1edc8600881204af4dc4215ba1f8406fc553c6e517d593f9df73a707202cb13b802fa35a8eb466ca117f71e8b8" },
                { "sco", "62ff73a7cd0eca6db02c93507386bb405b2ceebaf961d46b77248554b374170e80e0a406de6c0d6e226a7849eb6a95adf913fae4ca051039d7e5f19dd216ada7" },
                { "si", "4bbef124c9066f27aa8f9c03eb2f46d15b4fc4d3e49392b15d90899942d6a3e8f49ba207f909ddf950477634ca5fed0c6cb37483762238bf674c6b706dde5ddc" },
                { "sk", "8a28b7f9ad644cd23a06ffbd76baa38288ff2f1add473c4d67fa199c0aee0c15bfa9f70df29084050f921cbb5bd45bfaefc78534396d1aba0bb53980cd85469b" },
                { "skr", "d105140eb32d25551ba7924ac78dcdc2864a991330104f4abb9ca50cacf2d66070f9efb2d72ac23c78f58a87f55a8ec6039254d422ab2336d5b8d61a88280169" },
                { "sl", "938a1dce71c1e681c355a4400c8db7d0a80b5aacae000627f4a412c58db1d3d4cc74b5023967b6237e7e305b37adc089d40e83ba83a9190224a8ab8d9e72a9fb" },
                { "son", "c26639758864d94fbe1cb67debdc80ee8e57cca2b0b65018743188e6ef4cf5cd4ee3467110cf98301bec79a4fa72e0cf424c59a43b55c3824d5496ed26ed6799" },
                { "sq", "63ccae2ddc91ce857669b265faba00024c25df0fa310cf3c9fa7f86925d5a98aa6e5c579244cfddbd03691f624f16a8b8b3d2b38e69a1153c8f190c2442fd2f8" },
                { "sr", "e468220b929c129408782449aed567a6a0cd5d9cc0220f55c57cf009236867cc774d6cd9bdd86834bf76fe53f41f186e02c64cd23b7a38a54005ac64e675be92" },
                { "sv-SE", "4873733c301804053b56a410125abe0bb14f7a9d14e37428a5c23df85ea94f735536b75417cb5533fd60be12779da634009ff87c91455fbf07a09d02e0a6c898" },
                { "szl", "4ad7d1577ee933f7dd1a4762acc9d56e01e7f1a38a5898aa255887afb4a51a8461f5bd42d2063586c8e7799b5635adbcc1a3faf4bbe97c303a8d1412e50ee917" },
                { "ta", "696aa08c5794b184b1b7b4f05c45f0c5cecd85d6f7fc48fbaa408e4057f7d7e773662f70b912cc57d29595b8c774cd511377775e124bcdb12a58ddc222bb6403" },
                { "te", "d0d946dadd0bc2df094c88414a19976b063ee10c3df649e4e3c04242c973568d49e796845ef79b91923842adba49d2e746e274b9cfc1e117d08d8208776ce714" },
                { "tg", "15ce313a02be6a67e15002b782ac0a84ab10da78cdb1b9f0fba4461bc8b903078589ce0619f1b28df8cb3a467098eccef61bf670e003c2d40751134c1b17d09c" },
                { "th", "f7afb5e7dfcd6ce4c8bc22ff5ea554e705f85282eeca1ac6c45a73bd1a5299e0da55ee3d8e8afec9b08884df3c632703229f5b804a6ababe3c5d43f2d1553ba3" },
                { "tl", "a2ad5bdc649bbef5a8f89b83741af708c30926fd769fe917df89f5a26e3d9cb0a00db353c729da70bfea41c72fa920c369ad33054245a158e88ce0e6c1e8e191" },
                { "tr", "77796fc3c0d96be5263111ca3427db4b0aae9490dc13d9aaf31b6a63da0886a64184527ef8abd5dbff1354467e1a30fcc3f04dd17465abc5836bb4ed7af7ff70" },
                { "trs", "10ac5eac0f195d02523e6c7b24a739c33fabbd8cc0c2f2690dce100ebd121eb48905bf26f09f9fe3e0cad32fe5422b2a08d827c7217dceab6556f4f7e96cb004" },
                { "uk", "eff25b5d5a2d683fbd20c0a8dd00e4df1a4fe06d3cbcaed3536aa368c5fdc8a8ddbb1c7a4f2199acca32886405e46722f8d74f6eb2665e5a9a430d7d6ecff628" },
                { "ur", "c700377481f4a50f54db983bd39e8f6eac9bd12a02590adbf205c5e05cd422e3229c5de7f96a658a3f7e2d802d6f051b00a3be523b492a29ac6cd9e34802afb9" },
                { "uz", "507e2b27e687f89ebd02958889770735b7cde3b800519b56104da1926d82a6e00b84f1257c06cc1c1ce68c5c021c2b99e3fdec91d4ccab9635817ac2249d31f0" },
                { "vi", "d88ea38ff6941ceb555c1fd67078bd54a70a1e80e506b349cca72dc13e9c76294ef9637151171c728d21ccdccf2717444cd0e9f0df911d28b506319d8c97d7b0" },
                { "xh", "4dd563b6ab2a06c32e0cfd0ffada25df06883363dabed6cfb7f612609d0b61449861f6cc86b3cc9bd062ebcbebaf73c5cd963fb26805f3195677be77f076754a" },
                { "zh-CN", "18a3244a6be9f4a569fc2238ed2c64174244fa75533f3bd1f3c824f99252e407c4f5630eee751246f40d2b2128542ad7b6330cf721a09fbcaafa2d9e18057bd9" },
                { "zh-TW", "9c7c658707e54940278ae4b0ced48b32776d5f08a0ea56aa79468810ed05c63931e66f621cbbcf190938693962cee93315caabb259b80fbd0b11783be2914c55" }
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
            return ["firefox-aurora", "firefox-aurora-" + languageCode.ToLower()];
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
                if (cs64 != null && cs32 != null
                    && cs32.TryGetValue(languageCode, out string hash32)
                    && cs64.TryGetValue(languageCode, out string hash64))
                {
                    return [hash32, hash64];
                }
            }
            var sums = new List<string>(2);
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
            return [.. sums];
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
                    cs32 = [];
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
                    cs64 = [];
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
            return [];
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
