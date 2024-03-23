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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
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
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.9.1esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "ec6b8dd06be4189de9548419c58642e728dbad48dad525c908df5557295e551ea8f0ca05d16ec0a4f598f9f99e9a1e8a5c92f56833e410a536432da4db9038d2" },
                { "af", "abc186ba4a601053bc55dbe6bcc070ff456750f5f54482bd2f53a1662cb666f62969c13d2ea70edd91ad562672322e566a7b8f05fdda4371f4bc113621e08efe" },
                { "an", "1f04c01be4726285ab6d652a28a5bdaa8a9efbb65c9464cdcd63b5dfc93acc58246e568357c5399edc6efc902abbcb8ed064e4639cf4b0599f7e4e53584a4cfe" },
                { "ar", "9451201cc237d4c31696d6a3698b2da0f3d1b013ebf38c528f72615b7b1c7d9102e4ad21d03997a1b849f261f358d8306e272d53dec5412901b20ebbe8c257e6" },
                { "ast", "e85e5c8a2cb205bb4df701281666ebb50cf74cd7dfc6beea86289671a6c2bd55bc33fabe088614a9375db3ac3bf90fd858e2d6c9a6c9923dde0e9eff77425ac8" },
                { "az", "4ad2aea8789d5650fe10af78e3d316a44ab4e4573ce3482f53be6283fb8c32574b15de39e3f6cb9e4809db085ec653c4823a33cec180307ceb270c041ee807ca" },
                { "be", "80085ce1176ecc142ea81c4fcd00f8bdf3820039d131b62cc9b6e9025308f00b668084867f68d28c6fd5b008eee20b2cd76b1033135ba1a61e32343bc11651d9" },
                { "bg", "bd768b275d7681da6c6a012caec0b815f4dfe8f1b1545e6c486e883b60004b3c243a4a60253ea8377bf43f57e5fc0c208bec59fbd00345f24006359455d96965" },
                { "bn", "87fd60bd8e19301ed00c13f2a6d593d7f4ee9f17965b39843007f5817303cca95d306488381426f6e757076e9f3906a99b2592b97c77a093e7f7b5131c42837a" },
                { "br", "96c4b778b3cbb38ae6d1a1559540d1fc77365b397b6740da8cde3be23eb08ae8602f79885cde8d4baaa462f0f68c1499ed0203869dc04fd882dd99d0ecb98160" },
                { "bs", "7c975dc059849c1daf4111807bd301984ec160197ea6a3a3792618e617d74fd7c3dbee5424c7bf71e642cc2aa737915616bd18e32c8786e191510c94f37e80f2" },
                { "ca", "f3284e0c8dcb0aa37008e93a57aa8ec63554e9be5ac5631c7410b526d5a5d94af7a2a573775a2972106168beeef4678261ad0924ec6eef7ab665fe1d083c7ff5" },
                { "cak", "8c12b76763879a404639269fd76b5c953f6d641031bb2da7ce7ac3f6377e21ac72fb579ee2d7f51aebbf7c22377eb1268e5577ae8612a3e3bdd8b5e15c6c2321" },
                { "cs", "c681779b0dbc289fab2ad2c098dd8f1ad46cd28832b974fd5c11bd8959b9caf49efa1cf9622d472afa9de73f0b335fe4a0e320684bd678c99441bc88029a46ef" },
                { "cy", "275396494727261e64bfae4cd85d71e7b220d48ddbbcafd75bf088daa5142f05e7442bff45e6c7606cee5234a1d4b802e629a1580199d2a2f74d2425ec28393a" },
                { "da", "26559cf66b9c50281a8a9a84450e74aafcf6012ac652aac4690815c1317201a4a8c1e5a2f4435e7bd75211f1d54f86ab9d3bd73238a2db82da7723d2b9fdeef6" },
                { "de", "7ef8c794907d47c876acd49bd83b07fe9038e671ea4ee675a424b2684bcfbaefc30a8eee5a9a0e2445d85665a790c710933d763d3860e194ead50e49d36939c5" },
                { "dsb", "ba12843b5cce239364db784ff25f868026e9878452f7a0ed323c412155d23d565c6a8181f7843d1efecc4fc981b151dd928d25330299a646181885191beeba8a" },
                { "el", "fdeb17d5c1015329ce64e1ca6adc2252fae9a02a57eabca24b445dc04d0348b3ec1454484a53813c14609dcc7f32a8018f2349995d04dba92abee3f673e0fe2b" },
                { "en-CA", "b390dc09831eabae75524fa1a47fce49d18c76a07dafcd94df0e59d35639248bbd2214201da0d155e8f2a5ff17f0dde4956147fa810257bf56bc4e9c59d4030d" },
                { "en-GB", "ae26060a3005ef9d179ba7f000cd60468d2e8506002002df253d1b84be39228c809156636f540ab77762831a81fb5d753bc3f41c77005003ad31a988339e859b" },
                { "en-US", "e0b8bd6a241dbe74b50a62c9939c1d976cece2184f744df40be80527a897908b92ae6763f1ad0224937aeac3b4b37829c9ae008a22b8cac34e9470844b9f15c8" },
                { "eo", "3dacb9f77ba0819c696b52a23f1c0df6502f300c12aeffcc952c410202122c9837b7428f492d78e46b203776a08b99999d761960d695dbdf09615cf949928245" },
                { "es-AR", "5e20cf85be37e78b5e2f92772842c8ce8c7006001d338443f3a421129e27f95ceb21adda62a9e0f404d2d4afa2a3aab8a298dab18f0991257c831916a3282d78" },
                { "es-CL", "eca6e143f439811a3a57ed81ec0f1dc73283bbd64ee7b5d4da4525dd59a8113b968607390ddd3751ee0998400086ad2dcefb2e658fbf628a762b36df122afc7c" },
                { "es-ES", "bad3117a420a4b8f87d0f684daaca691d85a9ead9e39ed6c2410ebabd6e4df7f4924bc64443a7a97df4bdfe63359c4e98767e8c90a5ea82df155099f83f136f1" },
                { "es-MX", "0aa8f53380943baa929a38906f9b1af69a476883382cfef6ed88a4475661f1e93b6e871cf57a1b8eb0b600a36165d316d3853a96faa49568fc64dbf3c58c76a8" },
                { "et", "0cb4be67b1a7dbff2dcffba3c2ec7dc3730ab1bb64270a34bf4ef5c4f94142c2e9d7d622d691689a6813cd5ee66f324dfb9c5825fe2a5a301ba5a44e49928f0f" },
                { "eu", "a5a74e4e9e7b7640c559c9f3cfb0196960e0166185f8764d5dae5a8374e4d15c1a412dd5b34580f04c7ad274c0ae605ce507c7ae20bcc72257d13d6130686f79" },
                { "fa", "fc221b9b2c59955d2b5f62b9022d265801c48bc8476ca641d7c28212165e5ad684fcc17b5823a6cb8b6cdd912e2b308b4af11113f4cba938f33cfa89a4bad486" },
                { "ff", "097e3d71a4b17b11d37514a00b800cfeffb1a8e5d47d7934554fe92954516e4ec97f44b7fbad1ff3a21c885141d2d0c91cf51a19464da2d82b5c0a53e7785b6c" },
                { "fi", "79ce645589deda966b30855543826ea084130b4b02528c4ef24bb11f20b43ada23db07812a1091aec4a05da2ee922a2f02ebbc1ea4a86e34d00a94fa9f40b3a5" },
                { "fr", "050246d1793f510baaf4a7b01379e387d9efbc63a959c018668a86ccb83bbea0d4592024159bc9036d8061056dadece9d9b6f1d00564864df625eedbf586f420" },
                { "fur", "9a810f1a827e06b7a1682f9a10852f73268bbb1de17168166912632bbcfb13e7fc0b408db66c6208ac09cb8621907c427dc5930217e5ad8f0f679960937f0275" },
                { "fy-NL", "8efa85cbf1ba508b7cb0ef80a5c9361f2a3169a0e458cac99f90f585c3d8639440d8a323f9d5efdcbdb48d3c7a783d504202b1dfeba1c4211ac17cab8bdd024a" },
                { "ga-IE", "bb447114063661f62a2819b2c7a5c6d7b4a097bb62ede83c43ddccdd68c5fdbed17598b25edb6b8850ecc0b1d36dcac0af1ef34008a7ef48f6ca8cab151a0d52" },
                { "gd", "051a4407f03ab3a0b2b10a1267c82fd3f9b6371bd18801254e19a50039d782ef589f4c4a834213a68f8b272f0bcb78d2023fe6140331ed3cf1b154a29004e84c" },
                { "gl", "3cf154a2a4962ec463e4d43c9ffe953f1b374fce8653072ebe3381e7b3552fd9fb9e6de701163e296cc5b597284265568713c7c29085fbc6d619287452485201" },
                { "gn", "75aa5277508c061134bbac4004bbe39e6984086a96e75d757c1dae8e724ddb8e300cd8a57143847397f22708a078b7e0307f057a11db6ea31d2ff1ca8a196ac8" },
                { "gu-IN", "16abb4d25b1b8e376b3e64fe37aa72e32cb541d4aa178ed0921bb758a91f0fe5e2f30881838ceb84d2069d70f3eb30dd12cfd6e5989dfca01c1b26f352894e3c" },
                { "he", "e6c8dd3805cac6c4ff6d691fab0f2ce87114fe25e2222863073c2801cb203b555bc4a2a262c4f4873e914152ae6c8afb47e4a8067ee4dc181860f1bfad67661f" },
                { "hi-IN", "fec8aa85d6e6f685e70f43e4256a7aa9e7d0df1386781972c9a892a5f92b800bcf7f3a501f1be6a6f8af26d1769e5d221ec4091775a5bd17525936bdef9a482a" },
                { "hr", "5716553b118c6c9c33cf78e4c2026964456f0d4519bed12729fa625f172a3ac8553196be2edcb697472857e1abe9a45fbb550324ce6b653ea2fda3566ab48579" },
                { "hsb", "7458e5885b786db0ff0dbf1cf8013c1e66252744ed7768981fd7603611ded2ff36ba923e5ab420e9226b45dc6157758d29dc0b27226f55b315070ce8dde50a59" },
                { "hu", "2dd670e111111bd0fa2480d8b634978c3d2ddc832faf1a55bc3d794ad63baeeac46825eb0add6fbfa26fbda929c31860e6522eeb487a54b2b927f1786030af86" },
                { "hy-AM", "a3cf85dd1da265134c1ea603ce7aed7d3605d152a3ea7bb4a14357ab599cb10e1608c96f28d7759a04e108fb5842e5fb31a9b750cae0ccfd70a3223f988a5642" },
                { "ia", "7712b1878fbeac772a1b4ec7903a5e0516aa269251013d9425c90e4905a18eac914ab8eb369101f64a25feb78a3493847c28a85bdf6ac4f3de26dae60ceb0105" },
                { "id", "5dd476f6da26af8e0864ef8b51d3eb54af6fe21d92e3e5defcabb0fd6f211c18867783742aa6c5f2a5b7cea67ae9e18b29f884962e07b627c9dc973afc7506fb" },
                { "is", "8df513ea01b41bed1853d5d4a310abe3cb1d54e5632c6132b8b386223461d23312db7de86f2cae31f8384ea2e00fb43a4debbaede939c5250acd22acc4ce0642" },
                { "it", "38a4b16f43a0aedf99e537cf5a10e5b5bbfdb13881df27513b5c88b2abeb90f90f5fa94976a9cc6433f60dbbbb0d49218ec43893ad916ef355d8f10a14128d2f" },
                { "ja", "a20d623327c2f3df99b1abb87695acbdc4ae706d7c6c462d06e2141f7a6c85197c53a4e367660dccf32f3adbc7b9e44846e3ef864081f049c91dba9a5e8da4f1" },
                { "ka", "e8584a0bcaaa754c7e20ba2d0a6f49e86acfd78d17081fb2f71392ed342ea3dee1510d9ed9644a77cbe7b7d5e69fbe6876045b99a63d18439cabd3541db17f40" },
                { "kab", "de7bae281b511f77f4cf0a9ecbbce9613de48fd49c3a227b67282e3383cc5a8cf51d5def2c669239a8cc53dde0c13c416e55859776ddaa9eff0f0f8e403ac876" },
                { "kk", "15041a92b63331f769253f34dfb686d5505c26432f5138a11e152a3dfa9da2a16e6a0a29b8a19c8c5aedcda0e6b7f64410fc0634af80932585444e9c3502cabc" },
                { "km", "53b49017affa2db7ae3af7f3f578763e4f3703d3363e5b6e831e89f847b0e81870f1157deed632403699efa6961cfa1aa168ccb8287323f5e93b122f585ea369" },
                { "kn", "6ca9374061765568daafd38f2d64ab9d01d1cc04dfdd1f75e33f46e5d0ecb5d637162fca02a0cd8d1ad014caf5f20a9a7ed5b0b4867ecb4c72321daf61d62f0b" },
                { "ko", "dff5cfb99d6e2ba875a6a0f21f6e6be013f8d7f25181b3e62cf67da1cc23253a9a1edf9be529f032bf9bf91721886f9bbe51c7da9014df522b9b1b6dd30f2902" },
                { "lij", "c411a8e6a7b948dc4f49da18d9305a7ba117b740dd4ae8b16e8730ca8babebe790ef8e01ef762fee10e3a7b3475d46adf368a8d16504bbae8d57a14bf0c0bdca" },
                { "lt", "aeacdf2368baeb90916df6086f1878ccf2af0ba001f561f4a7f3cf74617f4fc995f5d952aef1f023e389e1ee6549df69ab1a8ae620d7dfe57b0ca42a530a8964" },
                { "lv", "bfabdd8b37d1acdb979ca77654cb6a5fdbad2abb9296fdfd5e45205555c571a8da21c3d69e2d55a1dbcce375b08441e53551693b1eb3853b5662ccb3856f4dcd" },
                { "mk", "271bf2e5f854eca9450a15e0c246cfe5c479d4e9dbc44cc799a7e6b8a5d13461969754c65ddc501e32538c4a7e71642f9d97b2d30bde158a452a0e4751fefd63" },
                { "mr", "144671b4c79d11f12135fcc95084a0b8f190d346e7ef00815eba7600649ffb3c8f9a47cdd0a47b36ababeac1f8fbba303fcb7406410589cacb9de78de6d08a5a" },
                { "ms", "4043917335d16a4f7f14c8256da6f41f08d09eeb290c966edd90be56129f955d30533a64313833a95d4e4d4d47004a71fff78b53c16a30f51f0a937e1ad66abb" },
                { "my", "10f8eaf88bba9615aa4485142d5f55499ef3da9d67f2db8e9d75968452d90665b79fd2b08faf7ae4d671b616c4da1647e8c4f5baf73accf652c860d8c0b183b1" },
                { "nb-NO", "5539a0bed94ef36153aad8655d794a9babc1341562256d5a8345f20152f118f254af0c141d2cf0b5b8803b3bdcd80b1a88627fe0ec9ddc289fea43e5926f8450" },
                { "ne-NP", "3511c70265aa750c617b381e2bd9d56a56831ff090951142765df98b5799990269eefb13607b1862f7c9f0c6fd945a1520e7ea5b1754b2906e399bf97022eaef" },
                { "nl", "23a2ebb9f803f98b25f46728eaadbb6a0288b46eadd953e72552bf5fe389af2fe187eb151a26b071d0db12b4be03a1d72b2338d5f4e6909e4db3e66e1364f99d" },
                { "nn-NO", "d321d25ad66fd20b932a9426e2940534bce50afb1182d0bb65ed94120e051f6bdf28d1a30f9abb2281425a335af0577d0d740580911640399a45d03bffcbf270" },
                { "oc", "0ac1b37fd5914829420d0abb568b49a7e256b51356ba7a244f7c96199111b11c30992bddd24cbb14e2cbd829756350a96c6c7708b6ee470e4ffc7f4b16527b83" },
                { "pa-IN", "34b90e05966f986a1967d00d3ffbe8265c409140755ca65d50cf00eb72aa9b7d391d2b25b334fd42d352a77338ad82e68e41d0fd4a4363dd66ce6707dc81f335" },
                { "pl", "80e517248498c2a4174403792a184ae59f0ce214948081ab6d4886b6493db5550e22532e493cd828a92daff2ba793790b1e399cf71cb4512abb012967c441e56" },
                { "pt-BR", "2b0437bc82e02f891cfb5e9cb1198a34a74b0c8cd8a0a00ca822f684f61f9eff98bdc764982fbab88d75d65232e7d458e01810a28fa8d543005cdf950d294cf2" },
                { "pt-PT", "1d70d6564fe140f44558e389fb5245b06a636b9f6e843f649b8b5861a9b48de2ca11b3ef4465489ef48317d56a3c867aee6cdbc20653f68252c66e18e3ca1805" },
                { "rm", "2db665332da67099982a9165d8273e1d47505da826808fa9899f04cad58049a8b8c0291d614772ecfb3103ae7f825cb377f175c3291c1ccf4dfe029956a1a4ff" },
                { "ro", "a355a87c7bca585eea3990cd9ffdddfa769f866fdd7c65cc3668b62b1959d31e9cae5b9d71d37b9a2b11f70b73d930553404a86265418f698d9395235c91a7bf" },
                { "ru", "c8d9a83681ef0e44189dcb75f7ffa457866e2c562d514b43c2ec6743f49b81f44123fb13b2c44dc274504208e855505f3be2186e11042bc492bd283e1a5e8e77" },
                { "sc", "d6cbd069b734d58f104d701c5829e27df32e347273c0e654873cbb6a03ffb36f6ded164ef150639484a028fa568ce360abae2ed1dcc471e5127d36dc1379cf8b" },
                { "sco", "dd745d16410ab66fc17b67ec053b0b9e3704e162c9a4c2af5cb374739475c59a96c388705dbe5dced6da74d23e2e90d9cf6c251e4778e24d37b3ae73be01d4ef" },
                { "si", "bb88aed7910315c8b44d570df9deb4f18f502af8a2b8e02e0ec6e9bf5a20c2001a1c901d7a6900fb5c600e8d165c8ba7af07b8e9e8dea35443a8b0ef96a8f047" },
                { "sk", "e54972377d5aab8aada4e94524707f15d04d6a0f347002d84f24a77b18f684ac94c3c40903dfa589acc6b7cb5acc662e57554f08d47820559cb86023fc743489" },
                { "sl", "741be814f5fdebfa81e5d6e968dd2080ea46b0739cae9274bb08a4c44622e22fa55f95d75aade64e26c10b8e3845b801dc4b956b1ac6d3d96ed9c13c5c499805" },
                { "son", "f5b5e0524e0fed0f9e7d795beff4e1405f599735d43f57d53086cca2fec270fc7a081b9297e03c3a5c923df91f477e6242087545195aa81fbd9628bc80c774bf" },
                { "sq", "93c6e8021922d08971eb4e6198eec59e9438badb4bf52b77898e257e9f67552e843a31a9688c94dd9576527e6b15862fecd88472b7b7a0b2dc992522655669ab" },
                { "sr", "3c940cf63f02c3ce829e0340342abb903f93cff73d7d933e9eebd64e8879b633f47e40bd72ae8c9a363c3ad1ac1f4bce6759d7273f4c191b04ded98725e4399a" },
                { "sv-SE", "575c3e6c39b3c2e49bc0ee4f48d9cdebeda17acda5c2a65640c1234f828db927d66933ec8abcade11091c2f65b39cc177d234b62c4738db7b74027ae256505b0" },
                { "szl", "af415686b06f5d23e29bea484ab51d4c7146ea523478a2cabb6475c475b1396e61e9a5c1336a9b2349fd54e45ef1e8b4a122e54882074dadb4eea7e108f13bd0" },
                { "ta", "b6ecd7b8fcac0e043f08d73cb4b9f6e58ca5d3aa14adbbfff1271475b0df8571a08385932649cef789de9c90e0083e7819c43a37373a015edd24b0815c9caa0c" },
                { "te", "b5802de2fb1be07c04798627f037325c6d5ffbdb3c32f34a9fca1c564894978ca30e3d1015e91136e8ecb0e4b677eb1a83aee188aa475f81c0ea6e2ad8ad7586" },
                { "tg", "6f336a5569c6ea2675a732f9e08c850f004ffaac7c56edbb76eb70a629dee9ed50ea0a31b121ce6b6f1bb3a25051c437b27b40b9dd98e4e35d33b954e1e2bdec" },
                { "th", "b4305b6f5e9dcb673edc3a011f76512fd3f20dda427abf0fc8777615552c82652bac820e8466038e74ffda9bb51b8590b845c35ad70068f0c925ca9ba09e16c8" },
                { "tl", "f10f803bc22d5a629fc58daf2702f3087be121d96dc12242029867216e3f9d7dc824f373da605f1a22d6a02c2375833212cfecc5ce607a4e2d5f8e91cec24251" },
                { "tr", "e84dd05f249a7dd410ada297c178d92f570a06d6c5b68393b91fbcff092eaf3ddb49c5f539a4e77ba40378ca742b63f33d5760efbaa90fa637a474dbf2f30a15" },
                { "trs", "4c27c3c7fde288c433c0f7f5429ac6aa8b81b5d552a84e68f2d9a6ac49553d2a1b9dee2f74ee89ebd801d3ee521e612cc9e77d44621c5c307939f24e0aa60b0c" },
                { "uk", "fcd60d55f2ea438386b9f95df46b121dcc8b5f7d6454068cc6b19520eb00ddce25bf01ba9b3bcb0288c9504065f9a9b2dd25afdf28fbdaa538a6f0467cb908a1" },
                { "ur", "c79bffa2cdac6062dbedc87877373aa73e053dd6ebc29e7d77e67f5a78bfc415ef0ddd1ad64707b14591efdc6565381fc1b9088f4a056ce7a4329b4dee062be2" },
                { "uz", "90ea95c9ea656887b84775fa80bf9f9e68673f4caac75b53bde64427710e7005a7ae2fc4b78b80333d81ff7c546696c6665b2c7dc12d98f1bf29417f938b076c" },
                { "vi", "e6cee56065b95aa6bbd3f6552aab58e5009bcb2350e436fb3455c7bb324f3490bab99e8f337a0d8f5ba20e7ba5e850d59a35eb0dfe11269540b361770f529eaf" },
                { "xh", "8bea34f685a15a0a60a8c94879d072e08c8737c2ff31bd357d9f66b2a9c378e587d10cac29f1c7a0be696dde13e42152b33311e42b805d07f9b1a1829ac04a3f" },
                { "zh-CN", "268dc933cf7fdfa3f1eeb6206af73d87fec18a0109db187ef14a05893110df0246c396780c22300bbce6dc61c640073d6e0bc58e1075d28c7a183e6e6c276f01" },
                { "zh-TW", "9bac8336cfc569fd3d1ed8dbb57631d79acaf1e328963f617c9cc6cac9d0ed6ec7696d27c076db2bd756149b1848634f58575bd67d21deb5d793e46fa9d45998" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.9.1esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "f3f02ca2d97573b4f351a3f9b1cb575363b0e2c16098d29a1a2aff11e842132f97b4a42b01c85b3d34fb04c270a8d3dab05642e785fc2a85ebb137a94365dbb3" },
                { "af", "af33ed4dadf4ad2f20d755b538781b77d0f8617de01133e488d2105c87fb9a592297e9a5f4f25ed7978230e859d826ad6221267380b5ad7459b4e46c97273a17" },
                { "an", "f19352cd6197cba87b24300e0fe770799d87edcdfbdc87e661eb2c7f6c0d0f249a222068c2a378abe045322c8e4039fba88ce326967c8821f49b557bfcd8452c" },
                { "ar", "1dec2baa0e226a896682b5cded34cc81b6484076e7320bd85fd69181f82910ed67903999d7b336d2e1cba992dce7fa0433c26f9acca197d3864024b0aaa8c0fe" },
                { "ast", "864b15c9cc0c74f24da69f797d0d8c17c81c7cd1fd2e44631f49c1dbcd0cfd8890a7368b5514eccdaa5fa6f85fe9203a0dee10afba7377422d1eae0e21c3184a" },
                { "az", "95aa510c1c0640c4f66b70ab2bec8fbbb07c69ecf9d2911c530368701f0370fe7733a4b9df0056c4dc14ca2c101e86d7a9dcc9b94035a2f1ecf962b7e7c0e5cd" },
                { "be", "a72726a76b12e5fd8659f5e6550c898cd6b1546ae16cdf7ab88587020effb12c34201e6c1ef5f0725db32fdb28594ae82430d30b7f2bbc29ba9562982f1eee36" },
                { "bg", "7742eded47dfaa698a87d36f35ee9672cda3b126f15fba6f71704e13ed68c02b3468f4744a661d9d2dae95b06eb8418248bb378abd5bf2150df81c11b86f75a8" },
                { "bn", "7818b0a42a2b481a9c429e253438eb2f2eeaf4b6a787e05f59135deca2d5ee9c3143b6d1c69bbe0955374d4a5376f6d86acff984da3965413ce58eff5817e105" },
                { "br", "8e3f8465b8ccdebcaace1f1d94f069b15798bd10f30445253897de2c5a62db51bfcc68fd643c3cc7a13375ae989b02fdc7bd532d59c9e54e1fc7a6e35662fb28" },
                { "bs", "b38294ab5d21e5a2cf4d2646d9f529ec3d92062a6a234ad7f438974e4aa3662b6e068816204a241d7d1e295240b486da4d02ecea24fdc71fad2d89fa3c64217d" },
                { "ca", "52ee89d500975fd7be4d71b906bcf7d547c5e74b973a276772e5d6fd5fd320669cbe4c9b430659981b6a04b1b6e6ca2d54f676ffdf76c214f7288f6bd9b3a80d" },
                { "cak", "78d6294af50d990487e052fe31ea2924f2b62126219f09ae838606b5acaf299d771eba334e1c4f64dd1d59c53cdc517ea6f57c135f4226ffeb917fc9d186838e" },
                { "cs", "05a4eb9f0f6cdf5b6bfca85cfc2b5093c51b78d464c7e982c615d63b87892a0c8a61aa8a10582d2e4e1eed60d7d7ca620676eb78396e18bc61023388304d00a2" },
                { "cy", "cb1a3aea1f29f0872f5cbf24dfca363b72536062ad5c8855d96001152f4847344ffb1c539a34d42c924e50314375d93ce475d9a55273a9166d17f87fd33523b8" },
                { "da", "b663cb297c7ddb5b95343dcc5562a87e1580065c84d9952cf6b46ed2ffcfd4c3d72db1efdc15e53113f10aff458ec91e22271c399ec1bd08b9db03d954bfe36e" },
                { "de", "6a6b2ee944fed4f14d9d5b439bdc9663f4e61b6f1a62222b19912c32c2b0f6f53f5e237071895dc63b27ca31d6afd74099d1d93e3572c5ca4f9c8a1297085bb0" },
                { "dsb", "758caa681a8593137eb4424c62b6a651212a64165898accf537e4cab9ece4abe2fc5df9e7ca3d4ae106d42acb5ef40383a0ec9a89819cca98650f94c1de17e9f" },
                { "el", "41234a85d20199e4c004f570601194904ac8b5d59305a601d7f696a6542767138422bcdd182229985e6042e607317cb93c44d24288775d244f050cb3d7ecd52b" },
                { "en-CA", "20199a6f31910d14d37e18d9b144e1e4b2bde75cd2fb2787e0134f36f176ab0c39cce5a5b2c9c836f02479390783752fb4f73dbd265e9c8ee3be68c85eaa63b8" },
                { "en-GB", "cd3d07c2bf7cdfb46ff65e454cb48a0d07e6e8b905821319848b100fb7b12546a8c6b8662b70c894f95ff9aa4a498df2c82cb0c37e139243b4a16b068638590b" },
                { "en-US", "1d793459aee1a76b786de13faf9d00636a0d2829d70e2de60faa50a88841a41162063561c011e2aa0e26b62c7163a8d85da8e3f96c4ea0db57581bed7f08298f" },
                { "eo", "6d425988799495adbda13aeff00052362782083dde0f8038cb7f3c3c4afa80f619af1242af90dd7e6bdcb1550434679c8712de23091e4ce8d5a8a92c75f0de1f" },
                { "es-AR", "18fe353b77e42256556a8ae9d8dcf0fef7ba5bb6b99dd47e2258fcdd2cdd3a1aedfc184932f1d65f54411010156754dfc55c584f01bcb0ccd5d2eb1c09a13367" },
                { "es-CL", "f5b55721dd88bf75aee3967ecb5d95133352c1cdd5fd19e4544eddccbfee988f597ff6fecfd5c8c98f65b07f75d150d458105c2f30f7968d3994089e444bc685" },
                { "es-ES", "a2f2ab9070a91c1476231c3b8d219b3d86255f88e762163f62e2484916648772bef4b11760d6c564fd184bd614f2cb914e69f1ddd621847983c06270a1e9b716" },
                { "es-MX", "1740ed88664111aaf3dbf8d85efc8176d3321a5712155a60d474e6a3031666b83d770d450b76d92f5315f5ced08b6235319123509086940291c1ebf79d65300c" },
                { "et", "9ba8a9b448f6214ffcb49630bdac348d4bf451a5751f16ad1aa74fd8b07553ffbafa910746d9a8da39fc3e1da4946b07e3c545942f732ed7173bb0dc28303e2f" },
                { "eu", "c62af2d1ccdbd0fee6f095313d009c714c09488c6af9e866599a5cd06ffdc7ab03e7ed7b6001d1c49d937b4bcf94634a75aaf1f4e497ca2bb4c370caa8979943" },
                { "fa", "647040beea91a9f7ae7e0f11e42a376e96fb0177fc45bfd85b551ffba1c624891219cbd01e0f4754161e0a9b27aa7b5715c9950854e7d78fa335c77571851f58" },
                { "ff", "6b56a671dfe85bb9f0b162ea1dea20d3c48ea02957bb3f4a052a418d6b8cc58bf487d15e56e4247a38db89d9e29dd0a62c6d2ea78a072757ef903ea3035d454f" },
                { "fi", "2092dabf94a5f13908a8480a9a8df6d976d64da6b33e52757a48287a2a5e3b985223187bdeb7ee56d97c163f5e302b22e3cc8a009581cefaa79a7c64e6fcd9ac" },
                { "fr", "0857c237e3c35bffdde836f606462da9c9ffbc34b96b94c33701e18144129bff2f20ff5907e400989c8292697c6335f7b1334f71f8758b46db8f1a56de8cff96" },
                { "fur", "d2ae73e0ff1b221e16cf66f894308e84d2c4cffb976133bb4b399c8b0708b23847698d415552790d5fdb5080b13599c11c533f4209ce3db2cc8088081d6249f2" },
                { "fy-NL", "2bd05cf9b4a64fae8de0c7dfc20b39e4a3f3c119cdb5345ca029a4ba9649f6abe01d0d68e5f5489db47cb726606e8bc8a036dd0f8814ff6b60b03069b2a29860" },
                { "ga-IE", "351ae4f6008d4160ae42b0468311dc411385c1650a2d808ff946a8f4cf77d0dd94380bb68c2ff3a0acef7c9b57e3b1119a912fbb90fd4a1047ce4c0df8a40eb3" },
                { "gd", "f66bce017b127c253d7bd6cecdb11aef79579419a7271fab1e7de20e42f8931f09a564e51353e192ede9166ecbad2b5b4f7205eec269f2fb1d79d41805ff0e9b" },
                { "gl", "801c94ec921693feca3bdca5973e83e90e5f7245e951ec4283230acce2c92f5728ee370c2a56b0df9af48553115f528f93b73227d9d4e0421d8794e5a0b14f3d" },
                { "gn", "db17dc11486f137d1f4f71e8ae9bb4be636ae47c1fcf5bf00058312ae626dba73a2b688922cc51f07383b5b11f49ff8f7c9fc073957e080494e83bf11499541f" },
                { "gu-IN", "ce6f1623c48b285baf43e6dd7570b23ed6e7e719c1596043f7cc1ce511af32af4aded65323b6387c1b3e1e7185feb9f2dd63ef39a2bc998b7467f8c8647221b5" },
                { "he", "d5aac502f3a22f7c0d5032cfdf44cc5c5d13bd68e4ebd9190aa8d6d62e658a9e2dfa276a59fbc7a0ccc77167e59aca32a75ebf2e933be04562b74e879b07a2f4" },
                { "hi-IN", "656ed9d8ac68c684712bf0814f848ac02248b9a4598565d94d035478e9c7c8c8e1c2519f97d879286c004d8a706305dcdbc5add15b96b647df48e96e836d775d" },
                { "hr", "7a7bb440fa90e6275b90d7efc5d5e720cb702906c0f7f648b2e2a2f4a2eb2305924f40e710d6ad8bcb1e563845c730c510d707500dbe9c7ac4b27b38ad874087" },
                { "hsb", "f9839b4828a6613ea4ab2661426c598a3b7f7a61352bc2e03dfd874a52755e95fa91a11e19fae67195b5161e32a63ce135eb6ae8b960fec4d009e329aeef71d5" },
                { "hu", "39428c149f2d0df6d3b96695ad8c5924604ec4e075e1ae76bcf7259e2609dec8a962466667063a98390dcd930ed76ec534e4c8861136b62a5ff2328f40e9628c" },
                { "hy-AM", "33d2134e70d90327212cce5b7c6a7dc19b757bdc5e6fd3ece6d615d1d4a73b6b3a3685963c9da20241e174ad39769489b844235ea086fa751aea85680ddaeebe" },
                { "ia", "feccffbaa3b13aed8cb27cccd8a11d553f84a5b06ec4ab251a2ddd95a642e1e9e78015498e6088630b485e23d6a04b136fa81c74889e8763f03ee98126ee598f" },
                { "id", "7929ca5ebaba97d11f578758be6b06170a616aeb7c98359ed58da1ad001a1849163092051a19ca01e72923fd047a7cf872b0c9e5e1f5245b58ed0e2137116f57" },
                { "is", "6404440b8a36a57d0e9e7f84c0a27ac3c45374327e20cd297ff8d1ab10ff4681a3a99460ba51e5ce640676ad1aa6aea22b530f6dec761a862fb196288c017d57" },
                { "it", "26371c06c26862587f7039536f891b058132453997b2b1be4e344a99dfe49fb4a1a21f7317f2acee5a2025dc0debea9ca92ad6e415b6125106bc18e2860b406c" },
                { "ja", "27c2182a5c15490998f5ab081eda3cfa67aca8ce7b41b22fd2514f4b4d1660bc6029aa5dd1f695a0412bf19a17662db8055acf97a724412e263492768b419b9a" },
                { "ka", "15951ce334f817c11fbe6c5feb317edf5f543a9d137978a6c43780c9f6ad1d10dc4533ca7487956d38f0b8fcb64d49b3e849c1b37b67ec9710ce22bc09aaea39" },
                { "kab", "58f566926d8026f26f3fd644e7a69b236125a6b3c23b35edc3798aada9f14a96e5440feab2439bd692cfdc51732a3768aea0c72022fb0e21d285c8a90e766505" },
                { "kk", "a5b89b48cf9150fc7c1b9de111e0002a503eca7278612ebdbb458a523d7769232a6378a754eb3e5e3e9bc9a1570e83a2c118393a04e1caa0e15fd06e6bcbfe29" },
                { "km", "924ab5e77cf2b20615c5c0558977557382843e30b65b6cbfb97918d0f69bd56434fe1de9a73e3bf5ce5ae7e6143aeae6a0a7cb3b3da32d0a5f3b3357c210e09a" },
                { "kn", "f41a4b2e7b5e101c03d7c73f69a4b3bf723f8d157fa42d13905619f5fa2c75ad82044ec4bd39774307a4cb7c2c570d0329d9d0dbbec5dc612ac8ebbba6afa175" },
                { "ko", "c70754fb23c901a16b69cd51d779d82cf30b5a1911b430e5975fa15f4445357a10835e92ed700e9bcd21f691e79e4d8637c86ba5c64cbfc9631ec6fa9755e003" },
                { "lij", "26aedd2d1e3b65f2fe4ee48746c4845eb19dcee213444c8a2bafcec852d3243afc91a54f65ee3d8fdb721268fd0550bea9562e35381c9a4c0a9783af2b67c90b" },
                { "lt", "db52f50c1fd17f5777af68ea364125e3e04a726353d6b6a832433fc106c1222054dfb55ab90e4fdcecf3009773fe83a3b47031ebbece7d319e65fbc9e08b1628" },
                { "lv", "a48b93732ca93fd92379001e8613ff286d8c9ebc486e48967adb6f9044d56a8ca0a932fc24656893f0272abde3b97ee6b82e99bb7467d759b47f6f0f5d30a550" },
                { "mk", "18ed78e04966ff2d23410cfba2098f5e6d570af7397c61450933d5925522339d73a35c3cb640a55840288467e8320735db644b25a702297af0dfa6c6996eafbe" },
                { "mr", "7b437238e73200181ec888727bb3c89cb5f67394fbeb238e75f2917ac927660e752b39fec0de90ecbc7c0720127bc882ed89f1f31d2afa59ac54c16999a91a12" },
                { "ms", "c039e6a869e60c2bd2e669016467c68149af15055dde5b82478f270de517ccd7868b661a3c6eeaa6b53f05e5b4c9f18d110e8cffa7e4b269a76322847c12cf2e" },
                { "my", "3055c0b9c2c8e371ecfeba0b11687a452124293a33ad62b2577943354981453391be4ac31f09e8d14067544cb6a727def3dafbee1cbc9b1cc774130efa239273" },
                { "nb-NO", "2e21582f978c10d5477d1795a6d412ddae6cfa49cdf480f39a0967c89cfd4e2fe4e03b93480aef4992f0d45a9cb55331c4621b02c69e8455f53a8a59a4b40f55" },
                { "ne-NP", "af097edc53c320ebf7c7c69eeaf01e257ebec0bde3f79889b7685558f1f37b7d6295db58337d02cd129bb0f40f53d6bbb606d22058e9bfea4bc021129b365fd0" },
                { "nl", "82df081951e361ea280c875cf881ef955f723b98966c7975296779ab551f900439733705aa87d59393b34787ac464f6220d7a1df02e75c9a8e6a3b865fe63f5a" },
                { "nn-NO", "60022d990acc7aa1fee72d066198560494f514cf74a7934ee77414975115841ef62e7bd64b4cd83c314bc6c48f1464a43aaec5224956d91361aa7505cacf0a0e" },
                { "oc", "02a7e45aa363e8f1cf60bbb62c01d12e8b4c0afcc3a769d3a236c169c5318ac70ae574131280accd3afe683d05222c78d1ffbe9aa8bfbbf4c393297d8947b92e" },
                { "pa-IN", "c50b20ff34fa7e0639f045a73a2f80d4078de5e9df40e946c00b88ea26181c4c68a68e2b19787381cec4c1eb81f21b3f15ed2bc720eb944b0ae9d2a2ea11b520" },
                { "pl", "d1ade621c0bfe7948c67ea59e0d0566107a546080bfc600e8ddcd4181fdb2992c9451e02bed2ed810993dfc9675c4ce87acc788e4ae21df37c1acb2c5282f86a" },
                { "pt-BR", "1fc098b7caa7edeaa2fea921215659126cb5124acabb27e1a3e4755b5abd0cca33bcd2a96ab8db887f6679b5f7c1ced9a2a49d1b06da826d14c3f173e0f19f34" },
                { "pt-PT", "765bb951ceab52f81273665dba71209140c22480c3c883f33399b098d33ddfe6d3531b5a0984332a3cbe7f70766181b9132370c2e028251ad8f7b2de1d18dd9c" },
                { "rm", "baa3735f8cb78d867cf1696f033d06800737d0a5f00933ea00ccd8603b31c01417a264de1642bd04e038a3f2090df059e77b589516cd78b808c0caee5756397d" },
                { "ro", "c5d485bdc86aacdf71cc9cfa53eb4ab20510ace51a69b5556c9bb606b4b0b515269d3d8585fa50f10df5b441c4fb94140018a04fe7a168562d95b3e4ffc5dddc" },
                { "ru", "933237a6c873a7f18bb3bbc3a5884310e075e28a9df9fd665cc60d9de6c72409ac9baa45b8e11f4668735f829f38ee263b9e958661995e9f00dfac6805e9095d" },
                { "sc", "859968faadad8ad1f6009d4c91965d3ad76526c32c7ff384c17d27765c1fa5734237dbd2dc41b9496ff90236ca562b6a0c6fc0150ec4dfb8c0cf2558484c404a" },
                { "sco", "95223c63b47219eabf02b1437b2da12460501c2d40ad16a61037019f3a0214232986caa5cd51973a17c9529c3d21d0602b3bd2c7de65b10617b3fb26a214ecf1" },
                { "si", "4a73404aa388149bc580b0024535c735894ebb01fdbe8c5b67dc1d25b650a2ece08a679f62c3608fe140d50ae2b8c87b016883edc31b0ea3f79d444935b74a99" },
                { "sk", "19b5fa90a5b88061eefbcb8975c8545e90dd0c9817a5615d876fa31fa0787660799c116bbed3b6fc163c5f473c6b34ab78ace306c3856f452c09da3c72baca1f" },
                { "sl", "d679bcbd7f1466651f624033402ab72aa7a7e33bfa29810a1fea7a6843a9c56b4a1d93af11ea14e41713ceb10a6b4c6e89f402873e5f3cf17acc010e5b9a2518" },
                { "son", "f06a8a02d430914d5bb38e7b0113846d17f00789114abeb3493cab2796ec24a0d27d51391a4ba28248f824300eb9c6d7c0d74ffbe725cd5e2133fd4803a8d7ed" },
                { "sq", "cdb998ee8c3f72d328a4671bff33f5dac4c0a3e174e95f0dbf56d9fcd9cabed2a81ab5765d653f3fbaafb3fd40797cf10cff4c1a32014976659007ccc9ad91fe" },
                { "sr", "3bf2b1e333bbb5e939ece6b892e2326c5f846389facec1a3f85ff732d5e000ac962af9d32e27fd79ca5db5c55bed47709e7d010d1110308a33a58b65cf2c58b1" },
                { "sv-SE", "0626715e58679399f916b6dd274e90a53a6984824aa81579e35b31ba489d541e3f1f44cada0cc1745bd3cb74b27231a732119faa306eee8f15517669fc8693eb" },
                { "szl", "81e6a372e852b5af3fd98108dd9e85b41867d00cafab2f2e8d78f0cb83e0e755cf26d04cbdea2bad1a864dbc3261e98fa06cf835c6bb4ba335eef72a748ab841" },
                { "ta", "f2c22ee8f97a70eafd5733dd81ddc13dee9bbc8c300ffeed2041f8f4a85f2a40cc08a4d3f85d8fd4f8b193188c5a1b514b0fc08953297a52c8e05ecdc03a2314" },
                { "te", "2a14194eed8d37c9c83cbed6232ea170b375d36756b4197cdff66c42eb420544427749834980aad0258530e857bdd92432c88b277081e6fe11a33462df5d7b70" },
                { "tg", "6b3448de2f85ad33c57865598876220607107641b3229e255d0399b92d7c343807fd4ef7273d1f682f7875a54c9f5de9472f43c073d6f53880a31bb13a68568e" },
                { "th", "da3c892e7295703dfa8b1dd31e87f9bf918a1b5a3b0a53a43c4d51c82bcf0f5d33978be32f5482aed7027f357f1a6295423a34ce8b495d0223b1ee5810a6ad09" },
                { "tl", "fe71af7e44bef417154ba316e76c02fa4cf647bcdeb2c94a824cc2c8a710fb951ef40c7f11912e5adb251cbc92e0eb008375407eb9db492a1c928abe632fbc1d" },
                { "tr", "0f0e831f0fa83fa084c8a22f7eadc540a00ed189ade27d57a8d1f4ffb4384f671bf0a2fa645ce7b483ec8c9c5a7fb59c9fe756e30cf1f0af089845e5cce6fabc" },
                { "trs", "144b468063a90bd90c23f97fb4c41664ebd81234fc48d8f1d7de9ba099e3a580f0ac149175a0dcac8781f7360da85d4b52378b5dc135c1a94f727fc2025401af" },
                { "uk", "100c953e0be9f11aa8fded58cc3d40a9d5b1afbd87232da36483a6a1d2c58db46563d7c1f21a0cde4b371c7c02efc3043d930341bc00deca1416e28be50f84bc" },
                { "ur", "0191350a0387c649b6f4bbe86f1fce30569e9a004af1770287dbf968afa9a7709837206513bc076f5b3caf6fd5c6afa170c9cb9e0d786d4ff92c8244b488295b" },
                { "uz", "9e5469035477fa422b9b2297b4f3fd49c90a1101ff90d4e151d59a9bfcaf38ad811227fbcfbbbb6483c35624a6a0ddb5ef315795465ebba75e657f693e223872" },
                { "vi", "620b06be5064fbf0dedd40d3412b3ba047a3e502c90785c18d5e93e110662557598c66be2e9960816ca1911e5271c554d20efe5ec5e193c05ea058ebe31db96b" },
                { "xh", "0056e008053e8fb57a356f7623b481bc20d4b952967e83637c227c271a3cf72c7a5c0670c892f54a3d843f35cb11bea4958cc40e34a82b83a8fd64d9b08438ce" },
                { "zh-CN", "e8f48163eeaa0d3636454f0c7484e35cec6269a9650664a8044f579670c1d34c5f81d043cca52cd50b99761b7503ce78a760018a6555783849c98a2a04faede6" },
                { "zh-TW", "41c9bd507f8336559af7f75b07b3420b2a729c4f218395df1e619a22eb0f1d1a3d171aec4cac822eedaf3076f5bd413a8aeae4609f2763e8333cacab3ccf0472" }
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
            const string knownVersion = "115.9.1";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
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
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
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
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
        /// language code for the Firefox ESR version
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
    } // class
} // namespace
