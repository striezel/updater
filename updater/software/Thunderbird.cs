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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);


        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.2.2";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.2.2esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "c626fbc5a3ce4e65a784c7f9bcf57649296ebfcad1b1eb57bc8761e9a507994939f1a44c0c669a3844c0011b50b4c3fa93b073bfab4784815b402bf8c63bd9be" },
                { "ar", "cc9b1e621b322157d695f2124051b111d399489f6b90618a7da6904fb9cc70b22bb2224039abda90946ed5fba4a6978edd92dd458cd108feb0cc4b81299400fa" },
                { "ast", "c4de305343042cb4dd318e96d24cd862641628ebbbe7163a486c62acb8a7a655336b8f74956daa182ec892a5af34a1884d51f3e948bfd1018865c782431866c3" },
                { "be", "f200d4d1d7dd6f23b4d890871196fe298ba5edc2a14367287b30ddb5da1fdbb31cbd5665008ee09738c7bd6e60997feccbbda10e2eb2a01ed72a1d884c49a465" },
                { "bg", "d48b4fba58cdaeb8ad6af443c737a3a37aaaf814268ce2783e1bf49ac825c3046c0570aff46bf07b34c021665018255d50b1099f11acc7f35fa0ad00f501859b" },
                { "br", "50b91b738240757888ee1d30defd3a1b1f86460de11b2fa6b1d1fbd090090350667b81b0993d337018bb1482a1005e58b6ea990851153360fad90a07015e2cfa" },
                { "ca", "826ee7c9d12548cae67b5bfd4fbbcde6a537c17af0b8b9149f8b0d726a99ad39c570c8109bc955a726ff4e62ebf94e6b7537686ea2ccf2bc7adc98ce9e7ab542" },
                { "cak", "388a21b4137a73b094e7797abef9c1bb128e7876243277546b1c75dae44124f2b6ec67c290190615b4e4e271eaf966bdc48e762f699568da119899e737c20d27" },
                { "cs", "754c33b96129a23a54b4695153c4b2ba9b8fcec0eda9b83a5b14bb9cb761944dc76b08c7d6d7b4ef0130ef50ba4894d5394df46fa93fc95173e7b083edafbd67" },
                { "cy", "4ffd03739e29bc2e610ac122262ac69087333818f93696bc8d42951fd2ed175da9be8e5b576f6a9f1aa46f13f67cbef63414990089173de77422610ad0ba45bc" },
                { "da", "afdebae84eb216aa1ecaeb407797dfb49a5257154f3d27360e3b0b1534a181ed6657ba2cdbe5df7d609d23fb7f8a35e7f82d7f92100c6db564444730b154e524" },
                { "de", "7da863ae4687615dc926f3615290e5cc5c8731936ef40dc95ca4c7fb63ba4785e7a199f3e0d68ecfc885b84f30cfeeadaa5c550950efe441daeb741f6de2179f" },
                { "dsb", "23ebb689e7adc89ef764afd1d8cf2faa50fd1e4c678fd818cf7b2e1656b9c0766642f42b473bec25bdcb067ab42cb6661be9773cf7d80b96924629216e94e315" },
                { "el", "659e3aa6145a1426dffd951febc0b7afad95fa32b81b2b4faac562579a76690187642c86ccae84d024e43ff02271e02ad33d470fd29b532a66dfc832ae8e21f1" },
                { "en-CA", "8fec0d00a3f9377bc6f412988095b9fe2bb026fb613cb7d2bb62f8103dfb70415d2650d0e5c29aba0ad229cd42ee45bb6ec8f93cdb11b173687b62ea3ab4c9b2" },
                { "en-GB", "4da2d6ccddb07171f3791616c1d5d979ee4646f8ad0f3647fcffca5fd9b5350fbfb494fdd33ce5c48b3d75c2eb48ca75192f6f9670dce486acfd7653260107ec" },
                { "en-US", "dd4b28106ba5fbbff66e1b259d259c03edda7cc9749935217e6ab91f3df1c548416456f6273741af7002beebb30af3a79c767baadf6db319aa25e53c5a2714d2" },
                { "es-AR", "0176048cf737f25cc3d2f89cd770dca926e19a4c3a4372d832200df50230b12df0cf266666da259208d5c4cfc60af3eedf8197382335733a9cb6a93f30482a4a" },
                { "es-ES", "f83b28f4a5f594c32542076eaa97f755d537f2a8d3d3cd588384f10137e0c2d3c1ab5753567cbd341ad8feea97518f0298e5a761aa05189b8322e7b2ee113b52" },
                { "es-MX", "df642e64c0af7f39f4c0f27313ffe1c33ccc2f3c67d9c42aaec86e8e55ff65f04ca841754fb76203ecd444352094d2e4bc326396fe7777e13b100fa53f9e4f92" },
                { "et", "a61aea9dc9ea1038371bbac63f9ffe8fec520f7f7e48989ade268e4aba4ad4705c6522bef19bb4f57256fa1f17c8929a790790b69811d0b01cd9750b3cdb593a" },
                { "eu", "969688256723029c8e8293201c0b0810e3694ec4d90defb86641e8b1044cac686e81966a0261c36a5641ae02cfe7b861afbd6b6192f407e9a5ccd1e9a2e5615b" },
                { "fi", "e3212fa3396984227ac9007cc43fcc23a9d988a7d3ecd5a336888d9127aa16868a31fad6546e321778d3b6bf91f314d65bd56df1bf2f5fbed0ec4edcf51334ab" },
                { "fr", "8773cce09fa97b5090f4dfd75553afa3aeefadfabeb1980d8ab897ab7af8ad2340d04c4b40b2daab726590949db07e3fc86fbca95dd599316aebe193749e0374" },
                { "fy-NL", "f2772404ef173c2390b5ea3ca175c8188248e0f38dfd68bcf97411479322c76ee743e03c564318acdb4d4bb14377b496aeca1cb1a280cecffb7d06da60683822" },
                { "ga-IE", "907ab7d664c973fa4f8f1b5b6ae72e187f80b4eb17830ef9985cac26145c96dc574a0eb87646a184e753a0910480327ac16ce73f861513a33be1880a35b41c4f" },
                { "gd", "2863a2a462401a023999eca98aaaa6ba946d10c611e0bf2f3672ed44b43126bc3836cf849bd5a73292fd2f83a380416e7bddf122203d62db519ac2f251028c24" },
                { "gl", "08142082d8353c9face6e8371377e7951cf474035104aa1b5c6be6f66bff98d2f64c9094f2ac4a646c4e9b4164db0d31022f92ac7d1678290401f94f16e2bc2a" },
                { "he", "78bd3d46b762cd36671f16db9ecd4b2310ccf95b8008f8317d96e6f8996c177bfc7ae7a77b417d458f48c1338854ce1df15d1eab1fd112d13b06e18cc12e07b0" },
                { "hr", "0f209f20d78bdd9e5b321f8cb2d9c47543a81685188f02f1a415069a916d0ba0a1f99cc09e4679f44c5d6b134ebaed984153bb6580e0000f8fdd7e69fa106d5c" },
                { "hsb", "bc785e267f5c9d87ea204081a7546f60dac177a0696ab3e0c7ca4f3835899ef836b756c68d59ebd52ce1ef8d33911f4ad78213688474b5f420086ab7a98607ad" },
                { "hu", "1168b68c3ea5e71849eaa86c61db7f53826a8e9c2156d360f28761fa55ffb6411f45c8519932375ceceaaceaaaaba6a50d857bb59bb783c00f6f848545807f22" },
                { "hy-AM", "e8d18e625f7d81b70d4832bb615ead025b2317442e74036d83812faf63a5eef80be110fbf92e2fcc682f7b5be67334e3649b924d0f6d58e20aee597bd74cc135" },
                { "id", "d266fbe75b5769e278d41bfb010a7b3ebce8f21393cd9c6620509585e68b02741dc8e6660684fb00d6c5a4ab11a0081fb1d93219261d708ecd3409a1f44f466c" },
                { "is", "2e2d9e941f68910db600bae636ff4861255660193beb267e6e01a137b6f8fdc2e922c0ab5363d62606aabc25c0ec436876e6685f1195e943f3a59932a1a30334" },
                { "it", "6c406509bae9e42d6808f42ae5739bacc86b4b6ce125a7a9a146abc434797d2ca6a631b441e4297e984f543b99b575813b5ecc63213ba6d870463361942ebdcf" },
                { "ja", "ef666e8e2d6644dfa4f8a833523c7dff26e0abecfdbe9d31b9463dfc925494d17abd4641014353a433f25d7a129eed7658e9ca07ffec2f799407fc24d6741ad5" },
                { "ka", "41982297ba1041789729d257fa81f141c99a22d5d3956f5606a61e62799710cc2c1d2ed566498ce0ce123b1d73cab4f18490ff48925dc797ba8ef5099e549319" },
                { "kab", "fd251f6af225725d054c099843523b8ddfdd9cd5b7d4acf51fd92337b872492d6c698e923ee66dcd0d61021ec572d0f2659396cd2bd9a21e056f4e57ab4d5a2b" },
                { "kk", "3032748e90d9c044edddfe1b1a675cfe901698d38cef750defb4f0972853059da3d18f6f1910a0b51db8c73b3fa77b34b67a22683c0a8e7f63a62345b4db72de" },
                { "ko", "fc89118387b4ac0336ecb89d427cad84b1293db892d460dbfc38c44ce2e65f9ad1843038cc5a443d36c2be4ac9e3f19a48e83bca1095a07eeeba129d3ab1edc1" },
                { "lt", "4be69cebe3418426cebbd89834c94083408a784c9b4e7b15c9426ce023cc1054e1e887856849bc5b6e762beb3044366d1325ab13920282f2201104bf2a97fa96" },
                { "lv", "a5ed5ace22571dcc9e91998052f95676deaa3ee4bfbdc1618839eb5e03c8be3df3277fa4ebd7256cb3724fa0d218c578cea37a8ba7bf3533899cecd9903b991b" },
                { "ms", "99a501f8507d2d9db6cbaab10abd98f51e2aa4875617b4f083877752d1ce5bd17ac9b1c6c5eea562c2e2f54a25c8744e8cac3b1fa1edfaf6d33b29ecf0af97dc" },
                { "nb-NO", "a99abc4e159470d6cdc85fbeee6243701a4c72c3c83c426324ebd4f895d585088409101fca17b3fafa3e798144bb9f93e8986cf01a7e66b7104e5b3d787d4f0d" },
                { "nl", "69412371825bf7de5bdd740e659f3333bef13e71c4df0e8049cf448fa7a7ea129202661b866b53c79b7223dc4943c6fac1038cb8db5387aeadd85771b91441a4" },
                { "nn-NO", "7889e077f87bb0451105b7ccbb68a406c126f1dbba662ce175ff89f254eebc2d2a3534f715ddd68a885165df0ee319e2f39de8aac395fa0c1e27eab20a2928a0" },
                { "pa-IN", "6af3880583790231fc4f2559646089ad9d22d56578b8c77eb94edc6db88996dff6b05d589d00ecdcb486a21ab861ce831a9cb313a01fec57ac42126ee377c8ef" },
                { "pl", "84cf31b6115567cc2e76d8b082db992965946559c464eaffb2f4c7443a78c8a3355f5cd3adfe6abf99ff22ec06259966d12cc4f6651d39ce878f1bef85f9feb2" },
                { "pt-BR", "ddb73a2c91da473a7de4a46241dd2dfa49dfbe3c158540045df526cc0a6a81218276b7937d3cbf1d4e230ebc54354d2dc39363077d6edbe106bc09c7eb4d9615" },
                { "pt-PT", "bfdea4303de005c1fcb919e3afc67c95c855ab30550a6673cafba4807307e8ce1bd0d908d22ed17fa985526b280a9d150a3aa69d85bf308970f4838805ad6d82" },
                { "rm", "a50cabab20da0311653adbee97c357bd3b9e4be0fb4454e3b92d494ab617fb8c1cf2a7c710c0b729197ca8e3d76f330d17dc59dabd173ab15252dbabf1341b5b" },
                { "ro", "f363b05bdea48aa4dd8591b1ad2b10b6427926cc094aeabdbc52fb778457382db6ef6f2d74dbb089d3efc955f441a296476bf6bbe33bf34d848a36bd0ecc0637" },
                { "ru", "e1aeb4dab44ff9d0f03f5ed9309c9de083c7bccd149fcbbbe0a78355863081faaf823ee51dd1b97ae7eee1fea38c7d57516ef80313ec55f0f6fd421f102d2438" },
                { "sk", "92b107c7817dd1be9f3a5607e1fe4df0d02be820bd7e1c4a17cf06ea8d54197020629ce67ffb14a30e7460267f92f302484670ccebb969a4e04cc541d86b3670" },
                { "sl", "ce11a0f21067a16d497a7c920b2d5833cc15acd0beca78ab74625c1edf7ad59cd1de736abaca65fe15ec51f84b0892933b57110327224acdbc05d8379f593b27" },
                { "sq", "d598d8476e0380c746ef8bf4c9217e2d94fade9479f3733d955232474e4c5648504b1a2fd2b5c0b13d5e8aa773b282e073b7a7730903f06c1afd3a682ac4ecda" },
                { "sr", "72b4d6aa86e88fb7b6d03603d04874098121a48daabccbec8b5e57d6685dd8a6536c4b9999a24144b05abe39b4377cb1b0c8b36d7398330edf8fe5c9182a0780" },
                { "sv-SE", "46935dc551e1abb36026583250156e70a173903171352e64b5058b7a4412f7c4f5cdb1337fb2b52812ffff44bc7b950181120dcfb1511707a026d284aa870448" },
                { "th", "dd35f1d6806233df5072de8880ed4c2a0cda0d0a18f108b0ded0aeb324dc84095fdaa6815c01538052dc2331751beef267f910cf01876f3e78b0333ee63307fb" },
                { "tr", "12d10d087d3ed8ebeee7ead849ab3132d993bf38df3d71e61160092473ac3a81585b0bcfb09c1e1070af310cdc722bc9faef346f89bad7b651bcb6e4f9bfeb92" },
                { "uk", "a6ea2e7bd0d51b92ec3c0a99254e65ccac19a792280b148fcb01142c4f13494fdbf2cde7dfe4662001d99a8e2455ce114c897058ccbcf1abbb0c59d2937e4133" },
                { "uz", "d9a0a5c9df15bd65cb0c882e5c51155036d1d3533012a7e5bb4777b022a7cb1ce9b052bd3279d173ebf81aa00754e3f14b178c205d0752faecd9afd5aa9660db" },
                { "vi", "7d19599de147bca99c71080565ed714b22f6fb960970bb62c12001a4aab1fe2a83e03b404c685e8790368b924381204ca46bddb29774b10f144681b2c758e9a6" },
                { "zh-CN", "38d6610d0f0a42467dcd155699f7d4503a61d6407a814fd0f9de6508e2c2396620165c30d3eeb59a53c48f1b600072be34fdf70900d52798791b89127a7eb259" },
                { "zh-TW", "2a526b6f80603b459d4a7b376d85497f835698515f56f7d8550457371748ccaa96f14f44fd4125bd5ea71c09deaf4b2b01815b5d77b9996212df2e732fc1cbc9" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.2.2esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "630144cf376c2ec4ca339e7c47b5a9d37b175df1d1749be065fc06615c83d3c1e08cebf77c283bd11025bb93aa9ede99a24d2b5c3b9c130eddca5a1cec0ce3cf" },
                { "ar", "afe60e6b2b09f10b7d14fd8eca1c393f0b020f4fbbdb2dc22d3133445d1d8aa16bcf1f63a18e5afc71b15c02f614a6c7b385a28f14ca77bcc6d80a29f6043e26" },
                { "ast", "676cb9bdabc24326f90c08499aa4d02c5bc5df869f987e8019e2413f1051dd9d214c5a3c0a157089cdf3a1953166cf2e91f039ce9d7a3c549cc38341ce46615b" },
                { "be", "b87a1fa878b8dd1e1945af06eebc3188d28d444065dbfaff456673ad795df6321a6774038344fc1e834b326bd3da9312931177e307b39b4712ad5052b9895b50" },
                { "bg", "5e872f9bfad5f6c7bab98c8f03e6917251077795de3fd7c6c92510b2daeb8b11a5d385f84bbf7f029faa51a286f1af2d012f5d39812325c4978759338f043550" },
                { "br", "5e6fefccf4d418e4d25e4182222fa644d800c3313bb2cb5b6cdceb5eb2fb6d7e03912dafa567ce038ae22d7f3ad0dc1a7302df4c985e56ab65ee09d5abc3aa0a" },
                { "ca", "245f5610b2d04251084eb6ca8a587bc8d3ea67044142d5c99387927b2abd5db1b34b4cf2228deb14dcf98333cc69a9f2f360812b43a04299aa258e52aa31ff0f" },
                { "cak", "542b418a27d9fd69a8ce434ca4769c9d56222dddc9b4b8b46b4a8400a5e5c907a3ba3dddbbe9672d9fc3ce6bafa2db27a327dc06010d64de145c0a894d844a77" },
                { "cs", "061723ee1c8aef9a4bb59308e589d81c1e9b7337a801a6265697e28222458eaf86432e3fec6c7f2f9474cc369c4c6a3a5cfbe2bec9ed08c6767e9c87ba896a78" },
                { "cy", "9fd4cf00fd2ba6ebd5934ab3ecf4a5b7ef3feb729cb926ae99b42b05bb62a2b16c0994be4595b5cf8897eec9a5550ba8d6937d416a234e864a5d6dbbae5b5d1e" },
                { "da", "4a415a2cad4f1328cce69f2ef49bb0b0c39eb66aa9d2d9ac4ffe09551146f412490dbae73bf284a4c4159150e8fbf30ba85237a23eda0c5db6ac580bfbb1ca29" },
                { "de", "c73f8bee1c75d0947be2c809f37106894d550ae081d3ebe64931bd80fbfd3a5144d0643dedf16b37c7101e4dab9174ed8d94d86dfce0b12593aeb110e3ca4bcc" },
                { "dsb", "c6d3a4d1fe9efe86a8d1c30f20194599eb9700c19414005fca968575f6c81f2c3aecfa96f0b66e62f28c12adaa7aee414cc0c7444977bff12180fa4064209bf5" },
                { "el", "8e2b34361060b0cbb103baf5d52ca0d5f7570effd473e1f33e392f12770087388f20ff2675ecd69ba0d91492d33ba2d3b6673b599aeed312f3a3b371e4df7969" },
                { "en-CA", "8e7cdea3f5bbc1c5d8d5282d60d51dc021ea191fc13258b165331d71a7ec4fbb5b81b33971c319673e11080c07773e2b6e6cd9bb0ea3357cc851eb485c09d4f2" },
                { "en-GB", "d1caf99e49f027d7201af8323d715349365f294a6d2c82614cdf839e0a266ffef5e36ddc4ab3b2854ee8dd3fb96da633bd80b9d3cdf5bed39e7a56abe364c86c" },
                { "en-US", "ffd48993eca8fa273ace66074786a459d258d7836ad0a3b3e601e8765f8065eb19c915233192c8cae02f466ab72d9ba3e12da86e365b0af9ab4cc3b208558c09" },
                { "es-AR", "87a4472d5c8b37cf8283e9e7635522b38b1c9a3b901f7cfd6d2bfbb1221ac14fbe818503539f0e72742bfd4805885204b747a9a2e3621a7ce44fd6117f30d203" },
                { "es-ES", "71e00429910246455c8bfceed200c7646344a0146044ef67d9e26b8fd05f0de55b5a8464049a9baa8b22f1c42e17dbda6135a57a85c9d0ebd6a90597ce02bdd9" },
                { "es-MX", "e3e9f21b2c112c14416444a034467ee627fef40b465a01006bad72cf59aab52acdf40ae542f2a2968875c149514868ad8360e0ce4728d8c326cff6f75d033116" },
                { "et", "6d474b813245b4ea34e0861eaa698ba2a3e63f724a529d0916d84902b973ec0638253f54d376185654ac20b45abba971e9fdf8c6d0c58e6a9c42bae446abd1bd" },
                { "eu", "ccaf82bedc6242080fecdb24b1df064eadd83d296a08cf94fe32f019111f6ec82d6419f66125c59af6504f54741f3c4822d034328582d3691cfccb71ae740d2c" },
                { "fi", "287edfa2ad5b8b3718e88ac376d7674f149428325100e92ac4e67f5b50155fe65f2d68132e3429b3d4b94d7be16a6a9d8c1c6dda5f03299f45d4e1f8fcf3b507" },
                { "fr", "e0fc0bc5f488f79a70bff7bb8649b1d1363dd7f8b0ea7e2d2c8ce6d6d2adec013cadf4a0d4da94c8d0274028f2ed61d63c943409b642cfc3f782b8c6edcf77c3" },
                { "fy-NL", "7214f1e8e961177b621ca2ac90a83463e697bab1367205afd6f25d074a2b8b21e23dbf7525897166d3a40ec81e7667cb0a0712c4cd873de0aad79c4a02130ca6" },
                { "ga-IE", "28e8f205f875300e177244fdb85d91b0b32c6faa0abf4b044508ad8ae41f3b44f6dbad37697f6591b712d3bc8e4cab0c5fc2a6fd6286ceabb37dd2e620d9bc9b" },
                { "gd", "57e0db414bdf73a21c823a3df5ffffae6620c608df2435713f4b620c2410b0cb0d01213a7779eef23d2e2dbc66557d81b4e2892c82c1f5d12b2e8c7cc76ef45a" },
                { "gl", "7c2ff932bcf28b2afa5ff02198479b53fac06efe5aaa20692f9ca4039e4d8c3ea6201693ee3b425a88405bff1d97d619dd36886182fa9919bf3e1c779de9dedf" },
                { "he", "778ac5f683620ab69a45320668fcad93276d4f9163ed76a9f13550917a53f779b03f728b2ae65c48e53e5f2851ec83fab6c7cad7af6a9023c405f903a8017ba5" },
                { "hr", "fa9a98acf32c6507b8293c5f1d8561c0d5db7498a4bbf8278baa19d39fd6baba659e4128cdd1dbecfa3f081f27d36edf05173628eb0c8cbd7e85f7d850d47ac5" },
                { "hsb", "19259703a53541d84b9b1a1aebcc550aab1aa487b031a9ef1be2f5df04cc7d7691fcd0e71d266c548ae62121a8edc7bf077b1e63e6dd1cba5984292c041bf72d" },
                { "hu", "781480a7722c750575ffc71d1ba00faf2d79c2de89bb0bfe54e2817a719da72ace0709cc265992013464573302280b21075c26af4aa7ef312535355e6f942d99" },
                { "hy-AM", "07253855b6e90a497cfb9ac2aa69362a0645d4350c12d447c928a15ca80e601f456ba448341b7ae0f42fee5a73d7445ddd98ad27ee013ff7607e86483850de0b" },
                { "id", "9fb97ad16507f627089ae288cfe7fcaf0a8f4df083194a4c879e1d125a1a47196bdc1af638ea1e0869cca9fa3c4df5aa09692776753d6bca28349b99e5771bed" },
                { "is", "c3ad2301f01d2465ecbf9c39df2fba876880e4d8ff7228eb4a8d81af54cc5cd281a8b95a2b9153e611b41e04d66617c911c9e537add1b77c31d75bbc16487d44" },
                { "it", "c6e65d29ddadaf3641cdcb7aea54e0c8bdb578db8e1f94c7b495673d460a45fd6e931f261861e63773ae1c7dc8c9696c7c76bc569792dd4309a47525eec6e9ac" },
                { "ja", "a0e01d33ae0fc1584ea8cb75fe17654c7779d0507c97ba95c5edb468d87e0341e5cbf029c7db9f377eeb04e1aceef09a0933b4bc1178f7195773b06235cf873b" },
                { "ka", "39b787112ac8c24daef935076dbca48485372d4b3b9fa8d35e68e5d3e7e359a034bb942e871435549d8d9e33fcabc842da70f30bcef9ae3be02d39873b235684" },
                { "kab", "f09cba0bdc1fa8001dbfc536b142f51307ef89a2ebf3637179112099478d2c8e49927c9f52476ad0dc6be04c19e882d5b6fc41e353bb202863691d470f7c011e" },
                { "kk", "eed0114e2e8d182d494fb17512c2f4480e73726de3330291ae69cf71c24f157822d258bc4b1ea85b2b3eaddbe5d614c662e950dacc8895f8d727699b69d67fb6" },
                { "ko", "3cb63de8d5cb7402e2feae0b3c6fc4ffdc0b5f64844673515d7856d10eb60fc6bcbe37ba8d36af64e094c50f5522c069ed0e7ffd9e5adb63b7b2c0e10bddd172" },
                { "lt", "623aa292a62d72070ae7af5be1f93a423c5eccdd43fe4be29fd501fa178f7cc04a52de1792b05db60ea0866a3c8e9352ff55acc0593ff76315d76e45e38e0062" },
                { "lv", "71333cc3f9d203279cece1a1a5a07cea3a98e3aea0133d758392848b1e39a35e13f0907fa8de3d49638343495077b382f8d50c08ce9afe055ff65910356fa2e4" },
                { "ms", "f20e4831d57e065bbe78ec05171a660d136506f29365e2517f1e5dde43df688193bd71a7c62c5c82c47b7331ff07fba112fa46cb1db27fe3ed2593ff0c5bc91d" },
                { "nb-NO", "9064a92ac2a1bac2cbafc07b43388b1824dd7615a8d30b63d0ecb80db9002cfdb6d1b61e085b9605836a2a2bbc28d6fe51932fd17f6c9747b582bf8b0e259201" },
                { "nl", "1fba5ba962b8b40d4f5588b5e329ff6253e6d7ae346f3598be5d6695d1261c58c1c261fd58f7421fb824c8c5f4622718121be511886e1467c93c0965fe19934c" },
                { "nn-NO", "04bde90f9820bc5631cba7d7ba66bd2b690a1c4dab641e0931a10884a56dea16fef80a14d45a415a05d418ddcdce7c0b8c9455d59148c004fdd5749bd522c848" },
                { "pa-IN", "593c6c3db03ae1a5197aa466b657c6a7135a43f683ee0d54a18e1fc2db060c33b04f62698cb7bdc453ff72d1b67a8988fe8e503ce79df48f6d3d6d88389cab46" },
                { "pl", "c908fda99c84ce19faa823e59f7027df89ea157a91a7c5f367065ace8c3377d0c3f3369e10d0bf88823b99a5a8c7f4be45173c83d0dac73d0a6cd371ae50287e" },
                { "pt-BR", "8c2632c7be1795dd7241ff4fe28245a71927db1c3561f27a7d404bb1c3d3a38d4a035a3f3f2728656d541c4efff7d145de85298d7250f2e3da35583bc72c2436" },
                { "pt-PT", "6e181f78a7b78c4a662f455934ecfd35e7b923182cd046a602840a6c0a03ac1afe6c9dcdb756b730ea2b4bf0d604f8005ee5d1bab663b48f135e39566c05ec11" },
                { "rm", "e470780f66b696f7d33ae79e152763bca4360d1dbe9a6ceb9e2b817198adc248f933539ccf228cd6a07c957bf170d476f8aa5d36b7357b13aa5e9eecd82164d2" },
                { "ro", "062ed3726e920e946aaea6d084f8b50e2ffe65c723fc6bf39cd2f90c65e3a1d942aa4500630e274e7c39f764046673cdec82a1d1bfb3322c75d61e50aae7f2cf" },
                { "ru", "a12c1ab9d1bd46b261607094a16d6af556fc08d842f1f088f7717486356a9f535041e5dbf9d655f2e3e4f5fb902d2feb65ff09ce6ea03b5b6cd8ca0fe8914d00" },
                { "sk", "49ebdca9fdcd41acc062e46b98f87f0ef7444cff5f863949e0ba79a78257d7e3a2955a79a7389ea44e262abda5dbf0cb5fbafe509a7416fb70cc00cb5ace94e2" },
                { "sl", "ab19c7c6805f058326d242d1734bb08cc34e867b4f6f36872606e96bc49e513778634ce8183d28a6f4456e55ba697a56f4af827499eaa9bf2d7ab7f42b391a60" },
                { "sq", "98c28a4ad36789118b6ec1d9d62e3144a5e821fa9190dd703267c2e9e40b046695d735d1c01b672cec840632326b38c87b8272c747d0dd1a3814ff2c83caaf2a" },
                { "sr", "0daee9dea7e1ecd3eeec5cc6708eca9d7bbf131ad21eee3899f29b42d952e76d63f9c26ce185f324693835eef6537d6f5dd1e3f064fb3a7f0f268a7e49c93646" },
                { "sv-SE", "c7389072672ad62ba7bf8f839d41d71ecff0f3ea9de7503af33439009bf353c2260c5688bf103d5fb3728505af34aeebe47395a42db5965c41e18c6bbae32f3f" },
                { "th", "106aae3dc678f5559448e82d284ba32914a9208d57aa16034a8b1d1843f5e294a6e2ff52101c141338a9d6926ee21efd63672fda14343b8ed4a3a94d8c396302" },
                { "tr", "e623964c8a869b2466bf4c64fc26a4afb40733f2d0082d1b1789c390813cdc604a7a13c289fee8b24acae0f926bd9f56093120d77885cf5ae7663bbcd2e9b922" },
                { "uk", "c76bb4d3dc16c9f36acc5c458905ecade2c97c63ded6e84ea410b2eb0d811fb4b46bd445d338031c4a38de5c12e91825b3525106795beb508d4a82997dc39bd1" },
                { "uz", "f9631a434bea42a9a445f977452ec5e8bc388c1161e17bfa558c88a58967e3123fd44e2e610638d43cb2792c0cdeddd6aa1d876233e49366c7a730e07d79786e" },
                { "vi", "f5437c0c477edc132edd16100ab1b7baa05f799d67de6fa71a7a6870958e17b0deab10ef913d3c3966d0704e385dc4fa1334f8aa13098caea28fe103061baa03" },
                { "zh-CN", "cb94791c171fd6b8effe76638790617e816aa996c48e8fb7946ad36ba8c9c0a1b58d246c984f2454efc48c88ce451d5a43362a323281a2efdb881261d5d610a5" },
                { "zh-TW", "b7690ffb92ff79af7b6e9030dc74ce734c60c6c24fd03212a19b47ff5f1f50970cac126d98cce15149b3167a807e00e0f0381684e0ed6c4b96e69c1fbf109426" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                knownVersion,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win32/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win64/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-esr-latest&os=win&lang=" + languageCode;
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            try
            {
                var task = client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                response = null;
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                Triple current = new(currentVersion);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/128.1.0esr/SHA512SUMS
             * Common lines look like
             * "3881bf28...e2ab  win32/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 32-bit installer, and like
             * "20fd118b...f4a2  win64/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 64-bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "esr/SHA512SUMS";
            string sha512SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha512SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
        }


        /// <summary>
        /// Indicates whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
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
            return new List<string>(1)
            {
                "thunderbird"
            };
        }


        /// <summary>
        /// Determines whether a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
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
    } // class
} // namespace
