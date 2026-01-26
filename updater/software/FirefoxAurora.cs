/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2026  Dirk Stolle

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
        private const string currentVersion = "148.0b7";


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
            // https://ftp.mozilla.org/pub/devedition/releases/148.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "cfd3b3013520cf99b47bffa080ff6ceda2f31ea8bee2d3196d0cf8dd5b789c671cac1db741da94f5cb6814538b47be7d15bf0f99e193fe4313550b473a828ae1" },
                { "af", "0872a4972153ccdcac8375a52f94b36a03de735ac75610952216858b097b4291ebdc1a4baa88eb739a5175b37da84fbfcefcf438d71612a833560fe0f12480c5" },
                { "an", "4ad89c423e192667222073f70e4f65db7cbf4d4bada8d37b4c7573a513606f7450ce5dc4bdc9e970dd8dc79bffcbf07f171f661af322336cd17cdda5c2f15716" },
                { "ar", "0b11ff612dddf29fef735668ed63e86fb2426c20e20fc5c994ce97d1cc10579d78bbbd2b02110ea468ea053e5866fdeca7bb6b2138dbc66391a4648bf8b30cb7" },
                { "ast", "2382f6ab7173ac60ad6aac57384befc92afb6aff038137af9a034ebb454ad20ac00071331ec9cee9438192aa46dfb70ada71d271c77dc441f55dbf5c48c85082" },
                { "az", "86704cb753b138dc67a1b7773e6c348ceab74d6c6f47afb2b8851cda80f9c37702ddda06f9e5f2fcacae309b15c8bad92fabbcd6d5e5e72b1943292bed82e619" },
                { "be", "d2b6efb3f2705e02a47da6899f559cab438d785ae610414681609b80784fc00652866bc06e3cf78ab05ceaac093a87c0a83bd9b86120585741a7425a52ca2679" },
                { "bg", "b78f00afa9cd1892fa179edc911da2b8a4fe0698a48284dfa1907e99e5d3c3bb752be5c7841774d1e244f7a5be46ec52082275505ef8aa3bfaaabc848bf6187a" },
                { "bn", "0fb647f4688d1d5078089d116c3c80a35283ec644d9623640042b2e7c0b313af20ef053dad83d98ef6a5f39100b81cb99b270e85443e23f959e258b54d8250ca" },
                { "br", "1ae2dfe466b44b464afb3d967e2de410f751f92755f668710240caee637530fe7091c1dfba8ed29343c4f224a9c5bf92abff40ea755173720f47a55d0dfe1092" },
                { "bs", "9f6c10dcbb25134f64124c4e538e999cdde3687717c6499902cafb519a7c2372aa77416d16c6d89b76a3cad8a2782534bed83e802249bb052a42762d162f8372" },
                { "ca", "bfddc87354086e9b3954a07bc47e44f4f66ac799f5488e636e7ba7487c8e0dc2745a8c14f9da06662707afbe04f50c20ea7f78f39b331167df02b0f404091e55" },
                { "cak", "79e7e9e9f6d048e22346a956beb876d39ffe2bcec957930af55d18a855425722a8d0891a91eb15b38a3c546c6490a8e472592b7301f5b8e58d65e2c643b3a1ad" },
                { "cs", "004659b3710e8867014c7a47da6c9df46a82c609f9b4d93c791954a4593c599484d400948e353cc92a23201688040f67b3b76805b2f26785fdc15acaef2c26bf" },
                { "cy", "5e5b32b4cf959e045ab4b05e579b843e65b33db6cd0c2d61832659ed3b9d526ce87211b213e2e097877c640e1fcdc78a203d00d09b70fbb6b705f392084e687d" },
                { "da", "45b669d9c20c61c27d1f2f0a9c54c8d88c27b8ce32a8e5580fa1949543b1f264bcf5e7ae5c3525246ef68a2b36f2ef5698076cffbf12e15982a05f83f7bf262e" },
                { "de", "a7810c1eafb205135c281847ab8621a6b98f6c13aead8177001f329b6fd28599e3cb3dc2b24c4fab6bdd0d022b9d3e4a2b65da494ba46c4c5a7b7ab10529289a" },
                { "dsb", "0c5d1f18fd280703be8cf755502ff7527ca44405435b6b52e267ffbd9b30fce348aa4a0f8ad827da8c349df4c68101c6027680b326de9e383d33ef479a5903b5" },
                { "el", "ff8727cc113dfa511591238120dd29eeaa4077b35ef26f2d5971dbd537e76105fc0ae887a4f3147215dcefc3c98efd35e00274bffedc74254fe2b6b3b80c8499" },
                { "en-CA", "348aa797c1c748b091ca7842ba96b5a6fc9913dab7a8bc8263bf1beb2dea389734d10b699f185cc63f68deaf87b958e88c5eb1dc83969d5c7bfb7aac6e29a531" },
                { "en-GB", "b694594ab9251d23aed3ae8a7227ed7823b4d27695ff6b0e3843f652180202971b88a8dc5139988168a95eaca1fc62e16db21e25b85c5be1f4f3577cd671a0c9" },
                { "en-US", "95464b6b41452a5edc13a93536107a2b17b725a4988aba3674f55aaa76b5d430de503f89568ad584432f5da87bb910fab50a2b9e47444a0a2e6c7663ee887371" },
                { "eo", "f11cd202397ecc5d03b7f3a6cc899d0316ff4907d470bb37a010dbb3e8e83bdebce29b0f8e812352e120ac7ffb5972591cb00d115eb6ed37055e75097e4e045d" },
                { "es-AR", "067693bf2eda1d6c03bc2d059ffdbf4f2c5b18ee8c8c32dc14e83da0db9b408503239af908e85828329de9a5d06788a9b6960782e3e6093d71b2817cec70e2b5" },
                { "es-CL", "c53dbb12629547232e43be870a5172637aa73aa760542f2fbb5e6409bc5fcfcf4f80cdc4f0158c4ca03f78c291478e4364fe29edf1bcea18146e51e25237b2af" },
                { "es-ES", "410863f0349ed776edd0b2e649ed2e3e6a16262599b3b10795d0c31e948553a79415c3ca5ac88bb55c332efb5b883515921de38ac282f43cde416e5fc121cfb6" },
                { "es-MX", "d1df924e1c08f964d5851c130e71c1871618ea7219e24d20a7f4ada34ead14c04123be1f3fe1ce3c6a7214f6897a3eb35c8a4bdb0e06573854f6f1adec39ed07" },
                { "et", "6e99592c14b51224485a3770aec093afd46a58dc56a6282c39541f57290f2b099720cebf907b3b7a5ee87c79eecf8d66dc84eadc45b8c5c9a0e1d882f9baa34f" },
                { "eu", "b79eb3ded002bde53098ea061f8288d6412b3d5b6a09d4a8456d62793bb7ecf2e76c780b099992dda946591643c09a247fba5195dc2c4c73fb7de559359fa821" },
                { "fa", "9e008b49319170cc71622848f5302c2721647eac5ee7b873e6982237e5e2bec3492bee29ca0410c89378cb3be222c762444607eefaea532ef4d665130632d150" },
                { "ff", "8fc23f9148fca0f066830ed6764b4bd0497ef554c09b19ec0da9ddd6b07f65d955ef3efac1c114b011e6f115df7ab54a2732dd7e1f34044d5ec2a4e373e6a849" },
                { "fi", "3aaca46f43fa1744091ce46efc5818ebfe9fb3c6e62e1ca05686ad6748fbddc2297b0ffcb054dc3e5e77f89503557af898299b40f993de051582815c6f1c9b42" },
                { "fr", "dc11afe30d6be90837f254db48ac929f9df8ac1c2d8ce2da2f2141031e5aaa4b37243d253a4f3155c974a194e65eebbcb6fb4285ab32a2a4583e75674c157e41" },
                { "fur", "6625a7a44c0b4c2e4c860bf91991b02f7d8fc597d031a2d1096420fd5c63b03402f2b61a1bedd0c29097ceb98d54e5bee829d37cbda77d9bb9ba039bf6711788" },
                { "fy-NL", "7046c5b5c6134f7efaf3519769419e0bfac16a8e0fdb7fdd4e6a3ba6c86bdfd4fc5802542e7a8a2f9700357286684c0e81adcff1eb9e5ac75dc9903d22944298" },
                { "ga-IE", "517af4d595f8723f6748bab28da99c556cdc527eae466fe179942dc7a7cfcb3460223a0b4e3d42b1a55b9fd953a904f2c5c255bde573d70e70f1b1b28af0003d" },
                { "gd", "309e9708239e5fd859b3c9d0cc8a83f97435b7062c8ca2b6d8c5ef26a787427def6d4fd966bb3220a5972c4448688e0fd3c4ccf7eb8e814d5083705266171a46" },
                { "gl", "c2b4ca77921a0a39cff6671886816f17ce71d538ab269e0091a4bb379bb120264470f041e5c623593f3a0be63d3597cea8e5c1548cd650fb9e8d75c27831d1eb" },
                { "gn", "364ffeafa3e2904fd936ff1f119296335325397c12ae3c8f3b1fef5644ba9685ec9629eed6b7d0dbc8eeae1561937f0b9091b2801701810b59f8b4dfe6c34d1d" },
                { "gu-IN", "9749cf99879d5bce6c8a7c6b57e0bd2e13fb485d8f89032f1e6ef2b5ea3b1228f7dce1df8b987d6d0d47b120ae72cb1ad28f94c3c7fcb8b8b4510bad3b1bf10e" },
                { "he", "e501eac686a7091404c9ce475ba6a3451067418b0cae92d7151438c83c5830b28148ace18511463f021a7b9d3bd184243b2a40f7e4a950f102601fcf4da9df27" },
                { "hi-IN", "e67773fda30a730eb79d12b7ebf6348f985e9d942438a94c0636c054886a66e5b44cf18b1df5b09f0d5599d63d492040841db748e7f91771341a1b4612be985f" },
                { "hr", "7254b10f70b994014c7d2461706f9bafb9822e7a098778177cfc45c3940a5ee74c5e3fa6d087e2d56e300508ef1854423cf8519f6043a2f18c14dd75b114d020" },
                { "hsb", "df06f160a3fed5378e65ba3fc5a4d0652f6131da08b93045d8a7a85df1c66acd1685d8c4c008b12bcb2703708f3237e25c2cb85182acb7efffd655530c3c2b09" },
                { "hu", "d134538f69671c77330a7c0610b48a74a2e93449fdaf96d8a3b26e168d9de24e7ab70d7dfe588ace5603a5c88e657f301477b47343142c21f456513cc959fc52" },
                { "hy-AM", "68ae03f3c307651fa7ff98e12bf3818db54b30d75dff7b2d9a340ad73dfc5c87d9b43c00c3603abe17b3375236ecfbd063397cc7b11cbb3d5864b54aad5d7c7d" },
                { "ia", "95e23406e9940d0a17e45f0a3102ef5471038f70ecae5fe05019cb31a0d3c3ae49702d72ed6c2fd7536576886dede7b937fe234189644ebc6190e8d0e7f28c6f" },
                { "id", "08be2b43e650af89b716664810b0a5c12d916a146787309d1483c902ef8fb430cf21f7c2ca18180d1874d279c7d4939487ae5dab160ecb923182f27a1f46e339" },
                { "is", "ec829d032723f090eab2649563c947bf6c858f69311d816328bac9b4c97aa5c63e2d7a66a43d672a2ae560b5744b796f4552c8b68032e4e97b566efdad9e24b6" },
                { "it", "e13e5aa06271f0a0dbe35943f612d254b3b11ee15ddf0752bcd419c4c368e4f9376f0ede8328e72af59b65fc29bb7407c3d8d8f22d2674c28c8f0955aedf93d3" },
                { "ja", "7cd787dc8ed97c7e86549edabb0ca8fe35cd32f579549f93b8986c0fdff9cc428d3a321c96df9dbe1ec1549a032356e7b86a9d6b6c68c52dab14ce5588e97a31" },
                { "ka", "c29c7ec7543401e8bdea9feb794717d86d8e0196e2fe438230c4160c4834fc21643ab89b6645bb882c9d740e99211d16121a8a321b55fe50d141672551484867" },
                { "kab", "aba47f802cc38298ad28843303a2f476db5f69056f9ef496652323eb8a06ab2269d1602fb8b1d6ac075e50edd26a09d63fe1bef766a7175db583fe2804529da2" },
                { "kk", "9bb5766b3e7ce7ae03dfea72c2664acd335c4584daac151afaf880b6175ba1f31956b3ef8514446bf37e03f33407be68d1154fb8a1c7b5483cf92210e302531e" },
                { "km", "106f858a3e79aaf122d8e74007371c10fd7b95286a5394d3599901230fc0e619f25dcd8d4259333443d35598540c55248dd44cf8c4b33938f9b04a80f96e9e21" },
                { "kn", "667742e9aafaff379b919a0c1c1431095566bffbb7252256d33be4fc06f16903dbd40cf209272187418f3ead66c827afb2cb060c53835d2bffaffe419f592e04" },
                { "ko", "e9b1ec25c26164de1436d14405a6fd800e4ea4e5ef48f5b98f027f9e99977f0c8232e8d5d7271cd499cc10c4ca9d6f067a21d1d61ab51715d6199b4f22d3ab00" },
                { "lij", "b6412f8ce82b422f0327a01e6c08a8cb4d8f99e4525c4c8cf899c0e1d5de5597bc1e8a553f60ddde11799c171f5eb8f83dd07aa791df55dcdd9f28c676387e38" },
                { "lt", "e6eefb471b88456b04028f7212094f17382a224ecd5a7f0f557d1758c98761d79f71b5028e3cbd8de1f639b3a64c774af86b2f42ed405ba854e3af8e8da17dbd" },
                { "lv", "d5a43d8d6c91ee74dbaf5c6b070685a7f8c889c71b13646c5c1ef5b297001a616d097af9784dcc885da93abce98a6a3552889bdacf3d56a5efeb24505b2f85bb" },
                { "mk", "5559e697c977f4f2d3e4551fc1ed0169b4475aa54699d5e6f8c8531cca2e93f8d2ddae0f913784c4c4eed96ed78997744816b7e3802d45d25bc0b9e76e0ae590" },
                { "mr", "14043d4c76cae2893f3d5f65b37f3d848a1746dd78a3739ff030509b8b73284c647913b0608a3e1af003afeb3f938ba9ffb2f287f971e4fcc5f8a4d1e3ce2608" },
                { "ms", "1accc133a5838eedf51d774cf16dd7eac604e8f2b4aac2357e9365b6c8851ef869c514deeae18245e631e76187a6d42ecb5bd49dc41d22ae0a783f824c9bd5f9" },
                { "my", "0ebdcfc499bc387604dc4717acea03842cb9b2a4ebbd57fa4df1ae5d420c63c562a7e3b116afde12a138362b32b3cf113b61e11f0f151c85f8667d0a6ba7dc16" },
                { "nb-NO", "d99b52b6e99bf7baabbf2156f9aa701867786610ae0f8b813416a35ff5d072d4b0ce951a8058b05118b155d41e9ff4ec808ddf2de4facc3508ccc8ec8a41fc9a" },
                { "ne-NP", "c47fca45b92f1e0b34144e53b3cf59e9d7e3df6cc6ee0161d5c91c67fa08a24cd1dd1fb03476a605ed3c86198163e33c8020089ca494454601e3d82271c7062e" },
                { "nl", "ce34741f752524a03098569765c4bc35af63b5a6ac76a8a0dd8340b35f1b282e831f6fb125d653fa2658f8195f3571ba8dd94a4d7da36ebd3f850e76d1ebc741" },
                { "nn-NO", "810c00c04fee3089758bc7b3c41fa970f8ce52716606e7f078bc2613ae84feb10d7a723eab2396461132e9a685d0f285723057abbd266edc119ff2de20db4544" },
                { "oc", "e56951c2bddd2d873a3c8ded354b2067bc0075bb0733a99190d238c37e302b4beff6bf77b49420ddb455dfe836cdec1e6b2eb681915c4828a1749ba25f6e2f9f" },
                { "pa-IN", "a0fda7f54637fdf0bbbe38c30fe1be1d4f590ea444abb6b9132b8f3fa3b900481c65f5791e6ed3b555bb42abb8135eca89ffa001915e37f382b38ccb370bdf42" },
                { "pl", "1dace94330279a3ca4feae2eee5eff99dfbeafd6a484f40417a09337d6bcba2f9e3ae84d558339f74b4ecccb9ce508f6a667f57b153804be627a4962e6783dc1" },
                { "pt-BR", "9b2c9a9a6ae0daafdb5eb129a6e3e4cf5ec39dcc105b75eef0da9aed7d6b92c7fc528d5528d2293e806fccb8114ea90169140eab68d6ec826101959ac0361965" },
                { "pt-PT", "483755f5f2e64ed90b3bf28ef780b710d8e089a51d946f8f0f4ed5be517978b6bac533c405e41f26629724336154a41bdcea5652f0440579db3307a342e41fcf" },
                { "rm", "55c01b6429151f2ee9b04372b621fd45bcbe16a285c0d953e2a4fc7a965c4e2a443eec0a50fe2506acb25860d45499f966f11b48c5cdf53f904ef732b547a7fa" },
                { "ro", "be66928a137c4e12ab5b41afb95b038ed2b7dc7954f5e317bf518f8faeec58404b93c287e79f3a59e01f3e47879f8bf9ab22e28cbc1240fc5b73bec41f15f076" },
                { "ru", "3f64b708abce0cacaed781c7f2220d4a0bf2e062caa1a78d176b5340f982f0db5659ac8df560965dd0c5c4285fd6bf618b812141a0699b7b007b41fcf829a8c7" },
                { "sat", "850352e4d3a0a67d09ec8d3d26e76af9227210a14ebd34a7be055465ed6d8390b2743eb933d7a1c58ee9ed807f19d1dc45baacf6e6ea23f7f6dd81815530e9c7" },
                { "sc", "be44e4405a615e12baef5d30c5a9bdb7c1ef799893cdf1a1870549adebd30a2e1736b0488eb26d82e61129b243eb425394a0d421e3bdb096639b312864d59443" },
                { "sco", "d7ec82b5bc6f92deda7cfe3ebbbd9ffcba8025d009a1bdf0186d9efd7f74ddc1e444b01aaf3aeb8eed4cc9bbfd34f22d6e4b1fbc2fa23cfbd1e9b8bef1a94380" },
                { "si", "b650535011eeee6315dcc5286ecb3b980edf6f7107e9e449b80b7e1374965bd7ce035c7b468b2b376ef3d3c3e8bf5fc802ae5e26ce854637f8cad46d5c57d2b1" },
                { "sk", "26ed3574e11de94bb58fb6c24c842e505c87381c0600d7378c4d6e9232f230e518b9619bf0ee0e97f490ea61373ba44f6df29b7fda21c231537ac3a03e51c0e4" },
                { "skr", "f0244a5b62975576870bd4d865499b74cd71eec46e321e52ca0c2c9a4e8ba3e5bcb86591ca7173a401abc51960cd09515d0120f74f70477bdc371e08c7790df8" },
                { "sl", "db99ce98f1bbb2759e18d691b08c8ac0622d93bfa0f3b6178f8098f6f064af71c9017f73ec7eab692387fbf0a10b14b1da0b4e7db013e963f9f262fd9cb9ac8f" },
                { "son", "f7ed623986b775f328a2078451d3b0fc7df9da83e9421935ded63785e6fa97dca9cd1c2f8e50c8ca3a481d8a9bbd9f31dd44aa011e66fd9dff7b1c58b0439037" },
                { "sq", "96ab69dd6fb7bb5918f152b9b0f9fc72e7b9605ec19e0f758c1318bc0a66801def9c5bbf7dc1eb83f3aed444a54d4ea6613b6d6da0b8ef1c4cd4ac7899bed6c2" },
                { "sr", "d5fba1c03a626a58dc7caf431d8b7162246fcb74312c64c1f69e549c5ae9436dcd637ccb56666862089ec94a554ddd37d934f3e94c8aa0e5645c86007de5a6c1" },
                { "sv-SE", "8badfa6b89a0d67596150f549bf4ae84078ac9fe672003d0e301c10812abe23218e92ad70b521403fa0bad27444e30932addf3895a4c0d7fc9da5197b8515075" },
                { "szl", "eddac6da863d3a2d18dc05b19789a5bec7f22458df0b4adf9d5f4444b395b2d5a1f87bfb27745375537eb879bf71f512724c4870021d18c5f58a756a9e7da4e4" },
                { "ta", "3aef850964b5e7b46493a78f5563911516d7aba377e568bfbe7928b01027eada5441f31cb948dc34f161bcf1aab25a3ddeedfc148726d0c238db406e09ee910e" },
                { "te", "502f2147da932462835599bf34052f1f4aef7e3ecf6789d7c49c9ec733fb6fdb8630c0749fb0e31e1ced8e8c5b8be433e3fb14e1ce53b56731dcf0de22b0c412" },
                { "tg", "7d0bb15b455621835196a18635d3f37c7c7bae841389efa96cb00c74d0866a4fd0a70c2351a6d236ec5e8e82cda0d3778e1e2852dcb9c527c1737ecf58f3f0c6" },
                { "th", "a70e8dc1bb11820d1a33ed694be46857d86713753dfc69c9c41327016120cb2b4b7a9dcb7d2c24f16fd41a6109f6ca590a1a452563382e2d4a6958743c5760f2" },
                { "tl", "0c5e35bc72ab51c3004af129f5e810a64412c916560e0fe1d74e553919e666e2940804b933392f3782cbd6f30929a63d8fe3b93e4c89354915bfbb427867c49c" },
                { "tr", "aa353023fa98de6efb3c661bc1b1bee321caffdb5839254cb0b1d01e205fe84ae99c5ca16b5fa14250336bd573cf9f1f35970d5663c85199ed24bfe25a4e732b" },
                { "trs", "7f76a0a2fbcc0044c4a52ebf2437eda16151e8ace5c6bfdf7d655e0601bca3809d9b0b3d821b40ab18478018154cabbee95c05123d334f0e2949a75ad8bb7847" },
                { "uk", "bdea38f45ec63624e43212547a84777f393093de49516083ae482a6899eaf752a0d0e79ae751c033c68523ea53a4d82a30fc00918a9f4fe4db4a6634efb54efa" },
                { "ur", "c99ab376610a00f271dfae2885f9139034dd3b3fa7f8f41a337ab268a2e8f9914feaa8017d91bec4bd0a8cba838ce972fe85e4d9d8042b8f00d1a863a754e491" },
                { "uz", "009c343f701fb589e8ccc66dc3163039fb9cf2ed3c6dd204f9a0ff5b83103331ab3450f0d28776a253319defec6559666d8ab5a3555b15de879c103f7d3a4d9e" },
                { "vi", "2cdc6e3f6c37c4d0a009856c7fb7e562f4146afa3a7213407fa5d6e62633df17ec6374fae5ef5d4c84309e36e136300c7403cfd21e53b4ad7cf8a08827cd9c3a" },
                { "xh", "61a214d8bec074dbc684d6fe134389944c176107cc7e5251390acd7f3fe076215005d1778816e6dcfbe424b876e7f83d6d8b45e8b3b22bbf5b70ef6c9277b020" },
                { "zh-CN", "d7cb0006c4da9fce0cb608814849a9fdecab143bbc91a710c36aca43eb63fd9fdd8457b161f41133f90170e917b5f0c253d2a22577b5cfb4593b70e428cdd274" },
                { "zh-TW", "3994c65bbf1f0a0b09fe2d93c40fb8c99d7a2af995d943aacc28f30267fa823f915120702a18153c212dce1430c4f398673dbe7c1015c6370877a5714af06ddf" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/148.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "0e4605774181a2e481f6ea979ccc6f35d9c5978c26a71fe8b98569063c21622830199102dcc268570905f2b517a72c1375bbdd3008227fcf4f3b48b9dd2d4853" },
                { "af", "b33098fb746cff52003087710648c527cafa3e5ef2eb26422a6984f5c450765666a851b3ca52013e4bd88a105c2f7d1136901679833edcabf8e783393b5cebcc" },
                { "an", "37267e62538b733ef923b2c5403d1b63cbbed80acfa7609608b5dc157a1267a0d9b79016cef39a0d02507ff194359dbef82a740506be1c0c8c46b6d1788e0a15" },
                { "ar", "a7fafaa45db3327b7e0590d8c86baebd50560c08cca16b54cc3c04188a861f2f2ac10a69717bd30b6260121f5a37248b5e8355a4e2177e1ee05e8aae90050ab5" },
                { "ast", "cab209a6910fe37a7126bc0cde5eb6587632f39d648ecfbd81fc81697c8c32c6ebadb069d048c17753b0d78c3cda0d655e4d00a8a9c11f9cb1a74ebecad214d1" },
                { "az", "d6fc8e5a06adae9dcd77accf4bc1a2f45df9f1467a0ccfa09cec4c47778eb8c6f7d306e1fefe1794aba3511336433194aa03f413e2eac20dc5201b2fb40403e9" },
                { "be", "1b5baad37334207d52e5a89e6c95c05220a8ce670eedc05df4cf265491bcc2f5128f6bee98673957f4118ef6250a3af77379e2abf36336e7d139d89e727584de" },
                { "bg", "0d9fbcbf752ca14725be8aaf25235939680471fb7635746f4f60af5f5712a5e6d00d39e05bcc24f547c41e0d74fcd7567b0353b17bf3746d283d960f4cf43a5e" },
                { "bn", "c9068d6b068e7b4a9cd09ddb2cfe23310eda5ad25a7d433f3f18a7a66a3e8c8c6b45ba733a0f5d444cec849a4dd65869da00c8f3e317b5acf63242cc544efccf" },
                { "br", "e1b2a9a0d1cc9a31ab3a3bb7ac186309e24d4daf4d608c999dda8a4767933981bd1f59473ce3d619547e0f2095fe108da2c49f85b70d55da60abd9248029ee09" },
                { "bs", "823bf7da5066d71bbc865ef9b2314ef4ed0dba8a8d9f59e48c0acd5c076d11c432f9fefaddd75941daa0b0e7326fc3d310ddda6667cea59472eea7cc7f945bfe" },
                { "ca", "91a049ed8fe7e16d9a5b2fafe757b4a066ac1d7cd9095eab83db6fbc4c6352423acb7ec5fcd2890e6df4245cc0df9c1e4383fc05b1407d49ea8090a1f51ee2f1" },
                { "cak", "339fe1d62ffae10234d4c4ef91877a1c37304a0b241cd694aff01e24437b289e24d539d6d9c0200a93f9855f105fde137c3de3922682e7ff2929fe77191cc158" },
                { "cs", "c3b53f583da76f25f05b69867ad2ecc5913a8d8be5692efc133129c2a2ea04219ad27b2eedd30e2b1326c24863fda0aeeecb267fa0c1b03e2a09f631c46f43aa" },
                { "cy", "dba23af94b230c110d24727a408d18a3e59eb28411907dbb550429b0d8172da374f91fcdf3074fc7fcd717682a10219d3945cdeee0ac5c19d8a7899f61377d92" },
                { "da", "4e3f92cd9665c8252ffcd111fa3ee4460132886ef1f61694d095456dc9255ed1238b7708c657df6d0bfdc172570843db970baf065e8c01d98a55a8de3c6ea605" },
                { "de", "a5080d22cdfa5b6d496e2165d3b93a2fa36f7760b607bbd4ab54257f0b505593149b2d763e55cf5282b60033412ddf9544dfe2d1c037497de43a76a1cab61469" },
                { "dsb", "7da19e90226dae7699d4957a015d20b30706c55e429034756aae2d177d9747f80e9672d5660cae3ad81db4adca853a2ec0a366ec638dc2aeae6826ca71bfdf25" },
                { "el", "079c744f4052d745a36986e6cf68e088a1692b4bc133a22f3b42ebcc12f86f308791769e99c4b465f0d12847417ad3ecfa11686b89f27b011464413bb0524c2a" },
                { "en-CA", "acfb5e2f677915272b933b94d76cbb3e6d5b09628337673ff77f83314b7664cc50bdb787b95eeac3800f3509804b57e1e16e339ed95d0d6bf2b29cfd8c4e3916" },
                { "en-GB", "964dcf9d2b1c12f931c0caddbc8bbe1631ef8c91df4e18ac86619a19e674ee216b2b5d3d39171c4638ed4993a0b6b5d508ba1d9c59cd775abc024004de203afd" },
                { "en-US", "98e83d3ab861b322df39995b760599a0849c1e1a92279ceca19940df9fad367e6f75a925fe2dd48eee40d2c4677e6adbc38170f702adda060ae0f7a71fae943b" },
                { "eo", "58ca1d3bb9aa4e5473da9151a4723811546fd0a9724b1c5454d284da9da91492cd20be4194b2d2d91af1be4054b025ee4cd1864cb5ee2a38fce10f366a2d0fe8" },
                { "es-AR", "8fd8372002004cf684e24cd4696352054c5186e299d57ea5ef735719fc2b16157374f0df348946d487a868b9c0fdf698865cda614411c9ce6ab4099e2432519b" },
                { "es-CL", "060507068bb8f832f5cec293d8ab8cbc9e1818e2ff18e1112e29c03bb7d5ea965647c22b73a4911706b47374ce5b5d7bc4d2b953bd7cecc844c0836e46ca81e6" },
                { "es-ES", "87ff2e7c445d0eddfef53fbaf924fe5a649e81c04b2f109ac443cd5198066a7f377976a4594becf983b3f1a17d72d4f93df7bf0b42f3cb6e584aff77e25c186c" },
                { "es-MX", "e4828672d8703f080a21c587e78e86cf804f8779b36cf43d84be5e2630d7a971906ce9830387d8275e61185fe00853508355e8d6992e625536f6c027ef7bc726" },
                { "et", "3ffbd314d239b2126df69dc13fe23f43acace6ae02a97111a07cb5a5cfe6f3d6521be967fb211359541949cff3325719f07eb3ffd07c63c582dfdeeaa7ec9940" },
                { "eu", "43c1f511494ba4e170c943c4dd15bd123e154d70e0e4e164cc16fbbee4a20198e44df01d4d3671416d6d497df003fc34686c71e9e3aa36be9edefb4b18b91b4a" },
                { "fa", "890b0a515f4925b4302549a45ded534435a685c609d9c6c5fb69a84654f205c3cefa4aa3170b28f7478ffa48a558d7e68a7a2c1793be16443cea321ae6268c54" },
                { "ff", "142a0484d26f23e1cadac2dc46d9b955d0a8c5e4e8273a376ccd492169c8fb92f53101d58490cf3700f4d5c9898835265754ed967a6de416ef9ad3a8fe792b27" },
                { "fi", "767dc37db8cf5b0c082f3c3abbc9f0cf1b290e23b12711d5428459a61c128e09c4e3cfc5b7e28266379ad10a26618a3b146d3c2803aae889af020f23387a4806" },
                { "fr", "8cbc08d456843f49111eeba33053bca790c3d00b6fc7d2c4cbb5ff5a55537babf5447d1d09a84fdc07343a5cea91c44e716ea45f2ecbcdcc78dc73cd0808d11f" },
                { "fur", "5db4ce2410e24ab1ce24347793ad5e9796efe301a23c39d31679216c9323b022a94569c030942837bf280b47206cd33e67188cb42dc4ac701000af3ac6614338" },
                { "fy-NL", "ed4afbbddc5eb1189664f8b5a40290bacf7188c518cb44748ff0cf78b020d77b69e7cb9f229aaa5861d8458b17abfda24b879f976eef430523a771941acf5691" },
                { "ga-IE", "de28b7de31ba3e48f77c933818521a750deea58dd0d603eb99e3f1b2dd215d84a9603138f1be2c1cc2d9b0c134ae89af669d588e96b5c83c4728845815b04672" },
                { "gd", "b12ee51f5452e36c008f21a7b745698db0727bf7c79fc06277676eedb5f9285fbb9053c2c1d660e13eda68b68274e3336cf02855747ab846e8a1a8d3e4c8c6ce" },
                { "gl", "5fe5da0fd4fdecc90bd66b7b975b8d1c02fd665a983f8d57a95cd9521e1f6aa9579d69ee4b9a813b5a506535609ebf7ee7bdb3d103a892ae14e8a20b19eaa7d3" },
                { "gn", "fd9a41971ca855aceebcb61a9cc4c9315c8b5a36d135255fba3ff52aa25dd47f81d786a9210c23a681d777d7bf1a16743a61ccea3e8f42c5495b6c2477f77f4e" },
                { "gu-IN", "97581d84d159a25740f3c661474a98e07ce4d8228d596257ae1bf4367fad8f2519eaf98e3495695e1a9a807b7e8b130bc36948a98654cc40fa76e0bce9230149" },
                { "he", "9b35b27bbda85ed34b116bebcff9f47a8bd0dd552f3e7d3fb2db5063f15a6d15c3bee7fb2a6aa790d2f9c1d3099c0e49928f021fbdf73b052591cf928e3a7fd8" },
                { "hi-IN", "7895f67b6ebf5213f7cc4cf87f789f1f151a355f91d3ce30e181d4169f7dbc05eed63a1b8dfcad863f91bc34002103ecaa8126c7bdbe0e6a7a17443a04b4e0fe" },
                { "hr", "0d20d034cb07a6b247943b90719331fb1c27bb16955a98c5dc8ae8a425dc9267274925bcdd5cf19514b3eae11ad8140024a1679fe7cedcc965aec4b391f2e95f" },
                { "hsb", "a2eeb38ff291ceb4254f1102333752c84b3776d0edc8438a3f63233bc61ccb7a3e4737ad8ae9b5cfc0982b88c2b11eb486f4247b29212d01e51d5693761a3423" },
                { "hu", "e7dbe074e6135f0c8c47865d59e22b37f8d33c7e872ffbeb11a409349d3e3248e64273b0e9a54348ac44982780dc81ee6de7af557653d66260c6d870383dfece" },
                { "hy-AM", "4666494ab405598a11b188fc978c9797b226474b488b633ee5e7da304c45237861da6a02491f812b727b52799e6b6d75b796d3444e991c679c7f8cbbe9100cf2" },
                { "ia", "474c4d9416eacb07adf6b978226990440c3f560a73c5f223b5fa4df0bc8997bf461ad0fc34d24dcd10b8d9fef8577626d4eec727f072eece3ca14f4cd1ff541a" },
                { "id", "146fcd2094ff2765b6bf5b3b7ffa7e1e62326035e269ad49e7f604ccd8c9edd86641f8ef199d07ad1cf8900b81b5e0ff9e15f73156930a338a614aa0e8047512" },
                { "is", "acb556ca7f08096117c47bac387f3b0cac76bee24e07cb5927d19f71201a60c3e91e6eb5eaa269ecbb07c3cfcfeeeb722fc64b98c4b9e8c65b7dfda5fa611c03" },
                { "it", "ecc7623cff9078011130c889539f1b563b03d66c362a8808acb2f84fd8aef3b87ed0e07021e768d175315b8d656c51fb1b559a86903b2ddc7d6fe8bddd3c140e" },
                { "ja", "a58fe105158409f3fe7de63e1c435c20ff6120ec1e3e850aa1d13c2501aa039a39235a4cd5d1a0497855a205e07aee6b15b9996e51ed0d5ec966b5d733b2bf78" },
                { "ka", "b81c892469b4e889c62e809d3d0286badecfacd6a9744d7dd3eec3157ed2c368965dddd3034470d048936728b38680b7ed1bccc383cd1596ec5c1113a9a51fb7" },
                { "kab", "bd6e2ea4bc62e0ae3af49fb36ca114351fe11f32c00ef7545eccf77324e271db573ea6d3ec184f0339d954b84034b9607861e89c4fd6d7c578f666696a3181bf" },
                { "kk", "848d509d0f7711e95cc777284b1d098134b7dbdfdd1ace43feb009ca0142d4579f555b210e93d65fd2c8748ec1fe0033b05c99f5738bc56cb6a7b5fd63ff31cd" },
                { "km", "54a19fc92c58c93cede60fa32714914ae38defdfddd890075b2d95d56b92856cf7a4f500ce296e4c195da3fd369fed8176cdb0e1b8dd67574a7793e5c9b7b446" },
                { "kn", "a6936e03fff84ea63e698cb6bfc8dfe3d6f849c2b25210ab868891f4bbb458d6bbfd6462b5a67e12d0744377b7a6a351ff7baedc12ad3d800e55442914fd5cf1" },
                { "ko", "ac50d545cddab61b6e81b21fca46a367d87ebd4e556581e6e9d07dc01a5ecde74e07d842caa3dd9090b82bc8710ef0704885b258e74ea3e511479585fda54eb7" },
                { "lij", "e2922bdc4bdec6bb2eeb74b56ce919f911d48220db9b352c7ea482c1bb6c38068c3ff001062f363d2ba94e9e25c4ffc3c527df9dd39ace152fcb85f1ef2e49f5" },
                { "lt", "473ef8e6b26c06951644f04e3d31a141b6430dfcaaaf340d06cc9581941af1f5c174c1f444daeb4b8d72183595d2ee461749aa39ae38fb2fc3ae32cd46fb2c9b" },
                { "lv", "a7fed8d28762469819c265f7e2b60ecb1dab513520bcf42392ae37096fb609e4e8867bdbb9f70c89c021345dabed2286863636e1b2e577a3aad10958810b3d2b" },
                { "mk", "df487288b8f4a1b973f583368120a8b6d30d5e823ab5f531fdaf3110a5740939206f3275a91d9e24246653712b7ab5d1a3b44031bfe10b65776dc56e48e8fd8c" },
                { "mr", "3834e1e27423c0cd287afaab7361e45ed6e3aea78962b9a62df23ca8ca707508d99fdd1772a3d6ddf09e89f9d9460869c687fd54af8382a2899c0544f35cc120" },
                { "ms", "ed5b142cda0509a08f6c206d2ef01e4b8f98a13ff1ad6a66fe9a9e6d1b8e0e39b5c51cfa11521040a0b52521474018962f67735f937370fe4c461858f84a1002" },
                { "my", "9a90bd827e82d3fa21c02a6c2c8186fbae0dab6adc20ec3d9b76525d26ad468d15d288e60a863072915d282c3a81140be352158b0e9539abf9c7706d7623c682" },
                { "nb-NO", "568c4ee01e56875cd34b79859ebd2504ab88aa001ccc31ff5703d3ad2c2ba24c2819b12684a597cccb8dae7b423a6d2321eeac7b24464990f9bd446a71e1e1cd" },
                { "ne-NP", "2096325a4825a0b491dae4eb7847a37732ac1967b11e8075675ed53b217236a362dc7d3005cc14607598b073bdf138c1880c7c4834571dadbc571366e5af461a" },
                { "nl", "2eb5618189f0b8beb826da16e366e8961bb04f53f476362c79d2071645fc4411ce67f841310547423a3b0274a5793b664dc6b3b97a906b8d2ecab71602b1cb43" },
                { "nn-NO", "96e0a609fe1d272111b09ca1364a82be3b1973d96a05471d1d852337af66a3ef1436d9f3d9eb1bf4902c6bfa07081759afe01fe0f4745ac22da17e1b39f3ccdb" },
                { "oc", "86e6ea59c5d5e7c75adb53ceadc8d30f8ce2ddce16c3465ebc933ddd7d8ea06a11c5bec6d28aade823e62967b1de718227c255b94065fa5fd4f48b1642c08d7e" },
                { "pa-IN", "6a53512acd9c68796ded17479ac7246e011a0bcdbf53ba1500efdcf92e983e68454f9cfb9a6e190ec5c856c4968cc15c5c6641a0b11014270726a11cf2f70537" },
                { "pl", "85423f46f8fb2f012138f36bcf115eab6c679bde6225cedcb6678f7f9e2bcbd0bcf7744523bd57952752da035b84c14c1b0e1beeae200014f1832133da10dd39" },
                { "pt-BR", "1d2e861148ba57815ec8eb0f13a61e2c4df189c8bab66cd0a05786a249b8bbdee6024dfe1e6504eb5cb7f785f56a9119339b96f79aa178fa03b580c944b6cb0f" },
                { "pt-PT", "2e51420833f4d55323490d168c064a9e667332d5c96ae43488fe26cbbd29b70b95c0460f4b92ffb7a54814820cc6eda5a792a56c095c06d391fa313bb831bb33" },
                { "rm", "939cb4455a295efd1fcd595dc35911b4ae520d9fca8524eabad4d78c1a2d9a7741411806bc1db3f6df99f2b5ac4360d8cb35815aa6a69a2fc480cf4988a443c7" },
                { "ro", "15a90151f36f5254670bfbae82b0d4cebda47c540c9d311ec8a45b0fe5dc01c071f9a5da8bc266dbd6acd58977073d7f3eb577d5a8655fd96fac6d8244bfccdb" },
                { "ru", "ea64729b9b6ee103e6eecfba781944cdc46578d2e2e51fbb6b05218e7da03bffb0baeb908482ff138cfbce6f49421209d9b0169ea4a588f2f7536ec895c95bfd" },
                { "sat", "30b1a53d8a1d33543c3d35339a31a2c7ca76f1cf1c0a90fba10ed6350c6ce9fc6ec01d53f6474603242a9e493f8c4fa44208f0caaf7d10a24b509599c0b3422e" },
                { "sc", "06cc7d73740cf8658c4f13fe8160eb6fdbff8439d2afb53616e72befe5b45751254be1f34725673ab7545b4c56d7760d7812bf73336cf96eab7f0b12bed86be3" },
                { "sco", "029e88f036f265ab3c6bdf1a1c268b3e5d87ab19b1a9c5e984456c343a9dd6e6822b8130c4d8866a4aca7f2e8b4069e682d6da4b5e80b8d2a4989946b558ec4a" },
                { "si", "3f00633ab173d2759a51c1dc101087742fc79840ac0d8a90d61ad36d0f5a8aabac09e44be72de30d7ae55c95bf7af03f40ebf4283c1a632351259ee31262d749" },
                { "sk", "85a04957d4aa3d90ddf7c2e09b0fb85d42045e062c19336900f398cfb31cbac898fc1b8ec1cb2374186f3398ea008463269678025bda9b803c66694156e9e452" },
                { "skr", "38fb270e52e006ad425862ccac6e3677428e7c7e4157b2c1f8bb23bd9f0bf8304b3b341fac75ef6cc03c832260b3b384f56cfa639089cb504659cea29d620430" },
                { "sl", "0356d1a4161b9fa9bd41aec2db3d9c2b9b08fbe8cf05a640a5d951f7e59dab7e21b2532285d552c02562ca0d2c47ed545160954b29aeaccea74376facdb10510" },
                { "son", "b29baba8ef2eb3adc74deabc76b7504ab5bbc4ea81b671573fe3be256d3ab35a6c0f6fe968a187a90420a7ff1d23c1e2a8377541353b832a8a7914aa18cdbb05" },
                { "sq", "b6265c05c2d56fca64febdd9bfad6200217ed5b2ed63c23efa7a4c22308cb0e5cedd204aecc1c75ff0e05a6337f08e5fa0fd4e225d827bf71fab39e0a30e4fba" },
                { "sr", "ae1a0ac149d6598390f35a4bc27c65290e925e28d8a8b3e687a8dceddc45c72c92565959505f17029cdb5388922f500e19788e20e34e6c31927aac40e53801f5" },
                { "sv-SE", "c834d00fa771c425910d2c60ffb5dec7b8e4692a5f4fa3730b4cfc074cc58bee311cd3736e0f1a8f020d925e99119ffae41bfe8fab3ba1b50285dbf3254c9a1c" },
                { "szl", "0294249b15d624746909f3041ce538d76330238efc69e23432dcb52c3784a4edd5af8a73515aa0d01e8560a598e99107c806af8f834ecd85083d77397c44619b" },
                { "ta", "c754710740b0cd064eb2162517b3a222188d72c4ef3b724b206d6f080597a7019517f4a22a81382dd22dd8b227ad4fef296c72371604f440031f2c511ece47e3" },
                { "te", "e8e1f949d91e21f544f241e30269f9a4376abe8679c00f1685444ddbada69ab6262a493d6bfa45a7f6039924a3c8e1ee4c1dd2c36ab24cc2496db1b46ca98067" },
                { "tg", "18ed2ad6c27bd5813a6778b7a7d1450ae8e214b78bad03970c04c1c4db62b92ed2fd1ca6e1cc4347cf7b567fd66534b41135bf4a108d9113424260e17a09980b" },
                { "th", "0525b349a65d0532443c0b48c936a1ad613569fb84f64d8a9671b04a0c1878f63d75c85f94ac77b09b844acefe20e982f0f91d16ea78921bea2506fb4fb3d718" },
                { "tl", "c07d2e9c72ef2a9baaa5878ab6ca25f7afd97f3caeb8c2618f48548a7e6176f9425c332eda06f2e9a2f7cf683bb4ecb763e21b3794d9299e8b2081e2f7ec97e6" },
                { "tr", "8c1870993e13840a8af73693c3cd2db5e2e1745bc346fc4f3a8cebed7ae7c2551ef6a3d2d46edebab3714d98e0269a833d14e06bd85271b294f5a7747b1466c9" },
                { "trs", "cf1cd4eb63bd663168ba29ab010e4cd58683cc38988f793b1bac6a1e8b0add92bda891ff51207f905e6ac45146e398691ac984c20deed94425d6ad4f870c0205" },
                { "uk", "392f5d06153d30c4356c6ffabffbd848326ef38a5fd98294c64564f8ad5d190ca44bcb4e1cc63c88c3f74d9b6877149b72d05ee37c45e001a7d7b610db06e49f" },
                { "ur", "6407c3cf7b05b45363401e3f92b4450f89fb6dbb04190d1250722581d5b85ef87ee6e64627ba7103a46f310305ed3c45b4abed5ffcaf30088eafdece872f2c5c" },
                { "uz", "98e08e38f0c68f96ca67c5dcb25d7156fb9dfd6f71027b58c5a647251224e9c03f8198753b75cdc1d3d609e2389af2cfd64bbe58274874e912b2622a84f730e8" },
                { "vi", "b18c8d7e1b2645a4da063343e37ddc36a42e2f5e4bc5a36d030b5c65306472e14c95601d5d22e15d3da0bf209f3520383c9c2dae5b3a4451d110d3d992558f53" },
                { "xh", "102c1b4c681074606dc9cd99f0e1539e58878eec3d07669252082cf0db2f333bc7d17a1bc5540d58617ca8d32eb36415b66dc911795ef7ab44a798354b0f8997" },
                { "zh-CN", "eeba4f968ad840fd5de5a6ba0e14bf84f880d1cf0af11025fd4cb430c9dfdd423dc633c25ac6927a7095d83401d1f039ef10022e611d761e9d9552e62f67a5ea" },
                { "zh-TW", "6a34d4bee0be9de5af2f2744c8f1f31281cf21d21b55ea3429541bd738a96f1b4e9c9591bc1a666baa028f660d50b1b4abdb7b7bc75501d51ee2d85fa7964295" }
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
