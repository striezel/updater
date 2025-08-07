/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/141.0.3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "5327fa911136c1a3192220101a659f85494ec8e9e837e4f6a309f2b6c255979346aef83720de2cb5ac9eee82ac5a7f412079c0836875b22ce4d6715803c523d4" },
                { "af", "8e17cf6ddd1eec3c32816faebed696d575d2d3210ebf67eff66fd9a94e9c69eee97bce9ab131b3ff0012f433594a2aeb29f1ac4396544405c8e7f887d4f5aa87" },
                { "an", "ca3879714e23dfbb4f0be6b2b8783ba44d99e3596d0c7b40d8d0b1bf11de42d3f6a4bde03fe0000fbfbd06ce41401760e0168d541e5498269d4049a439ee01b2" },
                { "ar", "fb23cc9393060d5cd5ed99bfe7fa279a179a80170917dbf8ce1527c3ad5da785ee435898601da1cac81bac2259847c1aa7869cedff2ea50c2117c00df3963392" },
                { "ast", "850e8043ac73c176a02fdae7332b3dccc9dc0c53e8f1b15004ddf311a14467081198d625fbf5f82c5fa20e56cf0b9a6b2df6c193d25e7b3bf6b4f69d90801ae8" },
                { "az", "f7e389a83c8909fade09a53939a503c7efdee9b031b58fafaf1c88a25f8c052a2e7554009f573a43664e3bd99e26151cd577e354c05cda527d272e5ae4d26614" },
                { "be", "797a4ff152f8e7f4959d6b8f52b963de8bc5ac888379812c55df23d41621f98b3ea7fd8d5532017fb7bbe96837a4ed42ae51f778362c6e66fbee7937e2959679" },
                { "bg", "d8e01b381cf00e25aeb1dca0aadf0114690c8cdfc8b01ab46f60406d03cc23826f527a28d13c0d3e0fb35a5ebfb6f4cc15535c426d41a94b312470fc98c4fbaf" },
                { "bn", "bb1a4658f442cb5db79127066a50d9d2c41c7e0c5cdc0da7d7aaece64d9238397426e89122ef0153ae73a8dc7108c36b812f93a3ed1ef80dbbe674115cb5ccff" },
                { "br", "6e165906cb6795d627f0043695ab5f63e53c04394e3c8053e5a46ffdad0d8b66bf035c635fb9793a76f18d400a4f812b075af99d71fd50e4572d8ccfa86bac83" },
                { "bs", "3fc604f5507562237a3773e427deb0ad157a665cbe15db6a43ead4ea27599d84a0f77142dffb4e64505f38b2963bf7347f503483d5040b5959cd528a1a5feafb" },
                { "ca", "bfc9c13dd3ad8d702e45b5d0d8dffb9c431ef28caf6c946ce60f47e20e19b662519c758401811f9d7c6769a994ed88a99cbccfc35325f1291fe258fdb49d4f12" },
                { "cak", "b4a2ca65522409ae9449fdb694ac6256af99cb48d5246dc61f4062ed461119de03873386dfb10a916a1c2d51beeafdfca7c01f27d668c6d0cecfc7169547b870" },
                { "cs", "cee68e6cdcfad1209ba5e221bb3f6b6f83c52f21a4f3490b4d63f80bec9f5f0ddd2bbda3ca1707b89b5bbf537ec1af3be6371176a36e403491b6ce4f2a816463" },
                { "cy", "6484de795e7439a88fe7a90759f0cd4586cc23dc626c6f911e6ef9eca9ce9951a3c65e085e8252856c32d0359f44ee556048d79695748b5d419b17bf3aed7d61" },
                { "da", "e9c756d34b50cf49c304fe5a5112af2777410ecedf61badab865f277a47a027ba799d81c7d29bb2b90ef3881158755c67616d61437b602232fe71189bfd34622" },
                { "de", "4df69b275b0230ab3538c7d0926a6f6857c74dcf207ce9be1866e69a7b9bcfc878b7564f610918b845e42fbeee178366fd616bc9a4d3ea997eaa4fece006932a" },
                { "dsb", "d538e7d72599bc3982a6b8d6e321929b9d960a449cf945ca6c5d99003f88a26c50a8ac6ccf038ff02c16954465d76359097a5528545cf4022c72c894ef64da52" },
                { "el", "029c6f5fc67fdd460e46afbf07faff1aa81ab050950478f6b69e98803ccd095646fd0684d2513f4727bf33e137fa23f0a7801390d4ade1367db443b457b6d3f3" },
                { "en-CA", "02005c2ea5c593f835a06124011bd8d45d4ec09a10f2986bd2ad89949a0dd8fe63ee99ccdc9b80eb0656d7bb1085e3c6270e486858929a5877f85e131f14876a" },
                { "en-GB", "7abb2536943886758fab9c3b96dbc39031673c310193362f19a2736294a704588e3a324ab60060abdcd3db782a351789da9c4c7dfe728353942c319f3a879a78" },
                { "en-US", "5ad7754d664b023b12d512e5947f5ca32b48da1c92321702848b7ab6f9b69fd0493159f91ad3378ead2422c93215ff24a13580714c0bdef3af3c805b05fcfd00" },
                { "eo", "ae0cca3244c646d7bd951290da8af10459f9cf0182a839d9d5772cefea6169e749407a46c79aa0cd133961ac1a1535deeaa7976678b550d53afd84b7b31d87ba" },
                { "es-AR", "bbd7c6547197006bb581fe38602b3cbdd1c8c80cf106a28fcd6c600289a909520203ce92a78689162eacb71640485beabfb4c07b13d992b6e16e5b4d89ea27ad" },
                { "es-CL", "64057ed7bcf5b403b3001a27556a38e427da553338c7ab70ce4b879cc603e9267874f5914b578e39bbbec179ac6b3efba8811831e32b3e107c2da77da575e721" },
                { "es-ES", "04eb7d940b7ef4bd09c9d20c30632acab98b921be9251eb309efd0de3fc068268c4ba1756db4ce9dec1d30379d97f09984164697314ab9f6636e7dfaa5a2c3a2" },
                { "es-MX", "a2cc9295692d561eba21259bbdc57ff6f9b54d777f045b2c41117eaf0ab8983a5c8de95f8dfdfc6982236a06574394273de74a5e69670fab4180cc56b09af9f5" },
                { "et", "e57c18c8bb5891489f27ce9e9f18dfd7bde96782f34121ee7a140336834b8f887a96a29e3482a17c0037a0c27b3273c73f4e6cfaf157f89a566879ce0a7de9c8" },
                { "eu", "488c7e28f7e6d6a506c940f7e776a6c3a5b5263b0f453f26ca339259cee03cf75f44e56ca04e7cc664ce999fa6224200b88ef486994d4da296627e87775c780f" },
                { "fa", "e57ec5cf17e46721e032806b14e0cfe83f0b061bb2260880e7b2b2b518e716292aabb902eb9405764369cd157bd2a403bfc742200b5be88f11ef9b785ca13096" },
                { "ff", "ef6ce8f9dd16e608a17505cd429329ce61a90a9c8fbc32b264acae4a40cc6dcc3e987663ccc16f1d91413004952fb8c031ba20957dab6566748c074a81a2ce79" },
                { "fi", "4f789aff3d4157cccaa1e93479b642d875ea2643fb7357fcc5c6dc671382083264403d60bcf6d6620efead51f96c4fbd270553bc39137bc6ccaa01d8bc017406" },
                { "fr", "4fd0e9bc69093774b93f78ad80d34476816fce0d6a82625c0d52f1d58e9b54dc2e0d8540a1382a63118126077aee82d19b23ea3c3d8c0fd16fb5a22d210f314f" },
                { "fur", "3c0a7e7419122ce99b8ca64bf0efb86ae66db6ea9d4f5e63742d3b1d036b47e7e44700bdcaebc30704e47c421447fac50c84f2eb87412cd1d75f76306bbe7db4" },
                { "fy-NL", "a7531f6284289b1027685ca7d0d9147ffe91f35167e12b53173dc96c29545c6752e1ee303f97df266266b234685592e1d35f953b2c0ecd9c46a4fc52a5c24dda" },
                { "ga-IE", "3525cf964fd783f3a7943a4cddfe67493550bc3cf82bdf56332408ffbc563ac1847c2847504c33cd00b3f57cd4d36f713b89297e1f64cb95307c7dd9f1068c4e" },
                { "gd", "3a318eeebcf125fbf99c597d2480c79e6000870d4d322a13de668af26441d4c2d1b6ead6007c5f0e6de0e0adeec08d1e67c92ac9c88e0ca52ee4c377dc190235" },
                { "gl", "b7f3cf6afaecaea7c945c2d86e86cc1f58a36bf4b976f640513ebbb2cfa0e7f174791bece38fee18131e294efdc25bd0916d6e76ab83789e00a6711331f0eef5" },
                { "gn", "f47bb539ff419298df34d1f6994c87355d43257a64902e56e82fc19a3008006e0b0d2097916326cb5e8d34af692e496a1d7ab553de96646e6939b5a1b5e903c5" },
                { "gu-IN", "d12908b391dca31003756678cb756a504085e4aa3e491d782f4cd0b9341a54e8cda0ee818846da5cc0316f7e91ffe834a5d4273d761574554ecc66c0355b58bb" },
                { "he", "e56c7e4546b44efbe5ac0e95b27c07465c2387aa9b254c6b99126ec46ff26f824458dcf5e5a32708cb6b95185f7f8cfaf605193afd34cac6e6a18f13c13f8865" },
                { "hi-IN", "bd5a88c429c12769bd83d47aeb5f8fbacb8addf7ef9155295e023d4f93e41d7a3354e8934d868a357df4c1cc908e8c410168dbc0f3b39975d452a093bb17cce8" },
                { "hr", "5a0254dcfc8943395c2bd68a026f588d528a1d686f09049ad2e0a74383c6da836eeee54605247c29d71472554b69b3e457d57f2338dca4773b2326de818679cf" },
                { "hsb", "d941b9bd08398818cc49e56abea5c0e17c6f5ad4de95d2b23b9fa1e5b6f6d1d4f654ea1f58e64df3840c2c5fb2157f138fc9dc2d9828d2216814ee282c8b1dba" },
                { "hu", "7294489164adadd0687cd416dd6406c3c6a9edb926d3001a3b2567ccbed31364102eb553c949ef92144bd686a463beecad127b55c0e6a5a88005082ded52a003" },
                { "hy-AM", "aff3d7ba00948b01ed97d9157f9252e8e57f80fe3b18150f7c3f780b3ce7e6a7e78b81998b8377a98e0d2bbb76e0201125e9fdcc20fb517bdccacd966d5dc928" },
                { "ia", "a4181a167f5dcecec7c3337fb372a0268314468cf8c67865cd304152eda0b770fe13b0bac05897c2a8e735295da8e852c131a9fe3843b5de7d2b37115471bb9c" },
                { "id", "5953f351dffa23ac866a8fed3cf1c76e2bdfa960d14b6bd8ec42a3c4251d55bcdf676684b69a56d065ac62d6767c84b216ac134c8f244c7d5e2530d0e0b97e66" },
                { "is", "7bb8615de9448836101936b3ebab036e46598786fb82d30dcc169386ac4e5cef8a62b9dad2cc4d38c47a7fb6547650a313da6a4f6204a3069d93c0b57595354c" },
                { "it", "0c174ff54f690bf75b15872df9561173a2e4adadf3fc2421a9d933eab43c0b9fb9d35d679f1caf5d3b20a3bbe4cd8d2d5a37f5536c7b2a163cb7145e215fb39a" },
                { "ja", "b72b39e8722b1d900abc9433ae8e0e33aef4cead6956796187d57c532fb6f5e354f1dec367fe6070c332a5c776b3b2333a319b9b18ef77bfba90cdf7bc156e6d" },
                { "ka", "fadf272949574525bb7c0ffa9e3855d9cbb72a552986ec479d6629379022180dd6bdad93fb23a36e09261c898b48a914799d5089902dc44c873fcb9bb5109216" },
                { "kab", "15941f424dee21f4b48dbca5b816e19156eeadf4cb3930be01e3161925e3673d170398bc23e4f53e67719a950363e8b15fa4d6ba788ff73df4c7ef9cd0a21b23" },
                { "kk", "a5c5ab182d4ce455a485e5ac8b1cac53f969910e620d90708222fc7fe995f05b7dbd367d59a98602694468f2297d8e71757510489f0d87895eff49bd9febe6d1" },
                { "km", "787c0b7f19a31fdf7522eada28a1598ba12e76afcdb91b22ca3b7bb2a26abe0aa518b471df24dd7c39031bbe942f51f66984597022dd40fd8cd0d581cc58434f" },
                { "kn", "d1f7f5f368f9ccb7ae1fbb8269feb48a8dae33e4f1bb1fde349c2bd542fc24f92c510153cc07c714b656949caf5edf48c5feb0f6cdb8f9002d6858a3c466b7b2" },
                { "ko", "3eef438430a2f5edf4f55c07d6a51691bd9701d28818f3a891a0b141bf3e8315d1d6075a9fcf7b35d1a72021e6eda60625662ce6ef7f618f02836a9c1c2b269a" },
                { "lij", "f0133c9dd4835cbd45661ff2d1c9498ddf59cc86f31c3d47facd2f17fc69f472d542fb538886c64805d7006876b16c7acc7b860fdca0d324fd3fba0dd252a576" },
                { "lt", "a1cfc10092eae2dcbcf39a08547e5300b5b154d92447bae73ba7713b56688c0dd033e43bcd9d5f3069bdecd2f92bad614d343bb2af67fcd2a263e7fb25a60d1f" },
                { "lv", "669f8a8ad2caf50ca1bbbcce364d271df6a465e079f5c69033a5b313f915e88648e2e3c90234b25ecaf541bf9ecc4e825e29f27bcc1718874bd47e208542c790" },
                { "mk", "35b47ec6eb4c6e9ac7f7b6fb2a32532520f9e5ce8cda01edbe4cf4c02ec9f718c6f26ad0da9e3cc2d72c8b8eb4ae366fdff7a335be0954b7570767ad8749196d" },
                { "mr", "5cc4d82ceea9b56a1a150d37d0f9676755904958d62eb26988cb8802865ac23ee272055e8efa5a37af8800e65ff07676ed844860afee7d86b82b48f9d61b803e" },
                { "ms", "f7e1ce40f2d826a7ac535c080a990c061aeab37403439b555683556ddc4dcac5ea819a955b7d86e6199db0bec19a587039e3068fa8ca503953a7ff7d3a0de0ac" },
                { "my", "996913dd9e346ab2addebc4078f768d54dff0df6a376ec70dbd78130d41285839cb35ce20bd0cffcb0ca8a4ecec2dfe98f36745d2faaea57f83509255a526fd7" },
                { "nb-NO", "935fe7b5f16317b91571f1f68e27c8ca48ef33741c183bd6c66af80da4a7dc3d329648b70337e1ef334282039815f73b98e505c3f36ebab53d7d9435f2c196f1" },
                { "ne-NP", "9e9faccad845c1393e614096897a8f7e082a00af5ca522ae4cc77aa31421513b9dbde83c0fe83af5cffc88e80c29ee161e725ec39760c57a874c7c0f0094dee8" },
                { "nl", "c7ede1ccbd065ed5253d1fa1f1937c4ede912bf052383f27f48b5f59b519bd2078f837331a2d2a52ba35edc8b77ff994b2b63eaef14009a13cf4a2f8a62c16de" },
                { "nn-NO", "e090d9f4653b74dbbcdf511baa1117ab05c6150d4995314dd93ee690cc6fed36665d589052e8a3906b9115c08ae30e412954cd67af959cad128c3d48511b4842" },
                { "oc", "9961b7881ab6efe3bc33a2356a88f8c0f5d7050798630f096ac8cd25c71f8d9717fdbf504c517174395692c0ddbefab4eb40a5d3abac52e065f05bc9200edce5" },
                { "pa-IN", "090009079ce3fe62b3009f881a5fdcc469006c05538c4a7cd3f329c24ef2d559cf6278474c05116d4d9815842aef3d891bed207cade044c07eab2113e877d88c" },
                { "pl", "b35333176a92c44d2a4af769315ed0db4f5ca7e629277cb0509c97b5f828357c5620e1ba77312864b6460bc3b41439acf3b0e35ea860f67796bbe122e9d74a88" },
                { "pt-BR", "49c53c046f3d710612dd8e8de09e92d87e6007c7b25adc8b4bc6b73446ef1bbdd06f40e5e1293e66e82a1116fa7276a5e03ac599179536f25c7077d75d07d70c" },
                { "pt-PT", "a83f4ed63f72f4fa0d5caf31f03da337bad243376bb91e75357b3ff9736d01ee1da85e30ce5f2043738b283173851043fca0c9adc86f6f729d302da6fe6864c4" },
                { "rm", "8b2362cfe52b63a0e803456fdb77fb3e9db05f58e40524a7ab6802a585bab93ea405a5fdade2b1daab734398a416d6e12e858b4fdb8448bcbe50314c42f29b28" },
                { "ro", "5aec304e638e6e3067781883211e7f278194ce6f6c0f73b93bb1273e36f1bbb9ee146320350a9f728a58b14576296befeb471de14838b59f9aece3845b5dc787" },
                { "ru", "228526d816f8f05aa1e20543f4cca43674bb45b8e0835e1f69d3fba61e42d63a7fb7d331bcd137e19cf3d7f7212fb2e3fb8000897608ce391a17661f97c09074" },
                { "sat", "cfd53b1110dcaa909459986f77b195af462d6f72c02079735067fda69b5238cd3328412c8b8ae6ded28b7823a041a24e3dd291d954c32fa4faa2197c81f43940" },
                { "sc", "6ff2b43617943310e9a2f6371f8eafad7c8d088a3387111420561278d4d804f50293fd0c8aff478b6a75b26b18f0b3d7a4892cc519b5d016e8806b6a3ab1562e" },
                { "sco", "f0e0b00c88254b0765899688a8cf0236719dfc5fccfedf77bd1ef0f6c987a57d8577a931e7ae5c15bc8855b410ccb3e8a0791963e2e6a51513e41147dd4581c2" },
                { "si", "94564136da5d8f3ff7c8d69cd42bfd0c6d2c7274447d936246c1532ae6ab7963019e5bb09b5c9bf1ab71dd9f847bbcf28dbff4146beedb4964fb30698012e0ba" },
                { "sk", "eee0c0108c35305474db3b904f556ec5ecccf17c5c46791b1fc3852c33de5446af3cd7259a36f1b86a1b8454011b2d307464b34b034ea345e295fc50cbf2d5c0" },
                { "skr", "746376d204e9334edaa3740f5f5c79e11735431a64c367e1af99bee36a7f83c2cdffcde4fd48e7fcd6d44e39bcbf02cc57857d35f99eae6c8e218c8167dca9dc" },
                { "sl", "64ca357d2b10daee7106bd80cc877ca2b5f0920b09da3f5c611c11ad11954dd9ea83bd8ddc46bdf20d61bc13f497f8bdb46884a6e63c8faab8baee6b98973a84" },
                { "son", "102e0fe1e35bdb0a84d256257000f6d47da818d77428241d1d03a0128ed55fead48a307b5e51fdad34e8c5149cf6db53d76b711477b27c5cd41a4ce6b281f990" },
                { "sq", "b13798061d84968d40416c68627c1ce6c123dbfd3f214fcee5a1bde0f53536f801d5ce37a1029623cc08e8a699d68afb5912eba16d143e21e3f5322ed4f50f7c" },
                { "sr", "e125f4a6b6c77fbda84b084ce08e433df18120bc6781c8c1219a009298cc66482525f1b29adf1b46625c8f09b3250cac48b4a699d54fef7ee90d8bdf32abb088" },
                { "sv-SE", "df2878b956836ab08dd7b8dcf6c993b2db45aec469c9c09fc0cec71a9ce68ecfc24ad2568f5e69c4675b74fac350d6b0ede4cabb9deec53915ac26f6d5391beb" },
                { "szl", "2f479d343f4c7843feb837b17abcb6c255337272bd08e3d4c3283ad7eb88119a1bfe3f37969b142de45c6f760bf5951905762acaf3c0d47aa767fd2ddb1e5061" },
                { "ta", "0d94c10892f851d8b1f73c6bb786cc6f49e183e0179cde4cbda59fd0fce9cff5d06332479a9f316aa0d5422a15277cf97673d0f243819f930931096fe1cd5d4c" },
                { "te", "7cc228d62fa4eaa3e379ec92e29f8b0f6239880403cb77c5d40d1131abaa17349e31a323819d08a3dfda0a68dea0aacec9be506fadaba075b5db67e8cae44e09" },
                { "tg", "9e7a8e86a2c7d6e620ae7b1455af1c24179a4f43558278d2d4368ea880ae95ac7d30433c1f8f2ae6e0e39a196c96b9621edb7601ecb7b12c8078156fd5c06f8b" },
                { "th", "de553a58966679e02e0dd538589a45a22aaccfc8f9146db073ab198ac1b971922724c7c659457b8c83810cb8c4de7dedfc1c17e83c63e441c0ccb047ba02d51f" },
                { "tl", "b21e2ae42d13274464279d7010539afd89580acb73127c02b508a31b9168dd747e974caeb9390c7db5e15510fa38875bff0bae0faf034243a22be446ac9cd97f" },
                { "tr", "7e3704306f0af18c692a7e03c270f05a1b13a586b07f6757513bf8e274278739c5ec4404f6f6375a33d2c95b2208b53839126f2389640fa2617feaeced9f8263" },
                { "trs", "4b43080f9209dcbdaed0ac03030067ea801f7cc15fe69513ea5fd1b19d195cce1f5a5cd40de5a97bf9c8f1b5fa7ae0c81255e0fa68fbc11d93620188f06244e1" },
                { "uk", "2003f1ba77c7e4a9a119da988ec7c82043c19811e15a726c22d1340ca46b84f1426f67d661925f848624605fbc907d79a84560f64c3b554f841d49f66bb6e05c" },
                { "ur", "616d310177a12a0579d0fe145d2782b041c259bab0ad0693558d42a5ca2060de8881f115c66b4ac54c8afa367b9c69fc8cd6e1f9a06cad9d8d4d1f90134e0514" },
                { "uz", "0b285d9150e5ccf1ee5737a525f850835432e63abd02c4eb4666643086fc53b69f3eaf0720e4da7e8bb7b9e727a77259c51639039d47cf8e2bcee53c85192481" },
                { "vi", "32398094cb37d02ba29b0b15da39293dceb2a554535dd9bba386dfa689d2daf675968f90eca3047a9f297d0c00ebc7dbd133d8e029992b642ee3e4e1a0d48254" },
                { "xh", "58543dab991ca93da50991950d232b0c1936c427d4281d3716fb3cd8a0da5a32247552d09a1f6c763fde46e6f7e75923923351390ecee5c268388c0491bcf05f" },
                { "zh-CN", "6dfb3bc7e2b350ccdcae43b136c5710786d25a816e50628e4ee4e24a4fa83242b59e490981a14e5df9608b6bab93203c135431f891309d597ee5e7578b701c23" },
                { "zh-TW", "7d7fb83dfa15e45f027f4ffee0d89141c359168b0319babe435a32b755fc67733dd0c6819fded3cc95371bff5f2186231239b4fcf5371dce4ed15c304cf524f3" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/141.0.3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a66b19d7596e044b1c8100128c745055d3c23f752e2f259acf56f5d1f7bf866f3229a1a3e063ad85f07e5f0412e510700b87228ff71d31515e58bf282f8a93a2" },
                { "af", "f56e724b3a4735db63bd20c382a42093047d5c6ab7093589c69f7866e9f9a7578210b9760602213513eddb390aed1ca79d4735d11d13d42e245a6c7895c35aa6" },
                { "an", "f6612492c2b7faa060cf97e4e74f80c39e2d7ef803cede28298614d2130672a81090d9cc2c11bd208541e3b8043ea025181d6acd13a4b64918dc1f5937823afa" },
                { "ar", "0297484a1b8db6d8b3bdbe503f43e40ff4b3dd9c578b64b0d3831123dd041bf204bcffc9f0d4ff79ed94aae7a532f10ebed511496fb835cdb64856d40bed948c" },
                { "ast", "c0ed929bea03cd0b15ed53b1e4d0757bdc3abff1f00032b5d8cd5f0cdfa0b3bb55e53b5f8f0b9d249ab192547ddadc46700380e1cd4d54fd60dfc975b5c6c360" },
                { "az", "f6c0a8ea568c603a58005191d1107e82add08595101250508677f4343844edac8a24a0bb553c4cac52fd4f84c3428bc70ad63b99f60400d4b0bb115fedf0e26f" },
                { "be", "07c3e25d7209e724a2e37d64128d078225c06d6756284a2ae81d8a4a5bff824fc63417d8ebeff7858e8b57e78fc6c4a60f1a0f1a565698399befac14814de275" },
                { "bg", "bfbe0fe3ef20c2e32b34b59cab9889776841b519e836618cc5b533cd99923acb085e5e6d148ed2c44c7b57fa635395e2f28d829e6e7c80fc5726d8f0af6a9c3e" },
                { "bn", "57a199205473dadcd82b67b14917bca57e08caf338a84e545824cd8c2a436a75477e5c6b89257ec7d02d2857c03f87c9a041d1962b7fa79da20c563e04aef87a" },
                { "br", "567cacf875bb35abf097e8d2f772d7a3c0e2db0271084bff3edc4b8a5a6bebdcde9e6a4a5163089451784057e484ff2788bc05da08e66c4e34230f98d8db4cf0" },
                { "bs", "d9843528f1275c751aa3988e1516a46005290f7ef3a5075f4c5f91896122bf0df2cec085c62b8b098138b82bb01a3ad9c5f7dda50c1a2a5eb89c38c11c812c77" },
                { "ca", "60b0b05b001cb9841c3eb64a9e742b4ccf1f6f370764118e71d94aa50e8a6a8716b625588b451795d813fe68d9f2c8b21164826ebbaa64d449927cef625b0fdb" },
                { "cak", "765563f3143e6c51a06e11b01e6df512c37c54cf5b07d9c2c1d23b6a65e9b6e5a247919226ebc9ae01174ef8ac058580a04429ce986674b7cf1f9d280a3c3ba4" },
                { "cs", "c76e44add700a613ec1761098c4535998f914b70f4de2a0fd4c314039141d6d42ebfe8b188ab6e86ac95532b4004fb594612e42bc18eb80a11e9683087f292fa" },
                { "cy", "7c3e6b4cd844a0ddfb0967c2b6b85ea5ece11f22303ed88c11f2ad7a8a8374045f56c75038bdd54fd2d523e17002c47e97c8b30841048347607041df3ebd8753" },
                { "da", "bb4757841006cfbe0c1f4592a8adbc7610a261ceada09b98a7ebb867de4b2efc61109162c048d1dbb08e28212e9912cdc07ea910f570ef743440afee5a325f06" },
                { "de", "dbae6a2637a2a1bb2e13747ffb2245f8cc54e91ae67ed86c4f17255d27fbd3c0480fb98a66c63d61b701c86455ef659eaa8ef8ad0d1fa699ae4726c3b439d7f5" },
                { "dsb", "311e0838717523056d7d33ba7d65f1f419412a7537f117c4ba579c904a91e04d215056739c14c9e7c22df092a9d0e896ce5e44369351930bbbbcc09af336339d" },
                { "el", "c5110080775f1706097f680e2d8c3da4b380ba020d5236a1633fe27aecd01f19b43e82f7355c3e7dc99d36440f56af4b16851772b3da546185725c650767022c" },
                { "en-CA", "349b10ac23555d5f501e5da0ea82dbc4e5d41859d18ffa7052afbf67eb0a4fdc8b01e0f0f5306ee50a929d73ecbc71c35e1dafbe708376f797f2ef034894a5c3" },
                { "en-GB", "7614f5271ccaadf7aae90f02a8f861a419839d3268a1e27ae2500c9a88865f751949aeb21b457eac7bb4db78cfeb549856719975cf96b5fbf310bf65462e8669" },
                { "en-US", "a6986371b3dcc6181d8b19a8c42cad14a2c139c2408882ff7d8f3967e7e37d2c05cec0c6af6189714598732180fe8aae107b99c9af397245acf6b9d879e715ba" },
                { "eo", "9fcbedebe036aa2a4636338323b2dd61ac4d1def4f93e6a38c8d8c7bab50d2d75e99bf2d472c69f5355b61ce805eede1d9485914cef4af19e78ffaefbccbdd80" },
                { "es-AR", "8083a89932ba2630741b6412787bf262df01c53236ca16ac75b4dd0c05ea843268313f511072ef53d32f14685b5f54716c08576f70d64c1949001285b5cac5c5" },
                { "es-CL", "a1ab00498bfcc0d2d81f33ca1a4197e294b76a91afc027b1ae1e280d11759aad5cb802d28e33449562bf40d142fe63e588e5e9044ee2a6b49ab6b6d788d785e1" },
                { "es-ES", "6c7a54290858df7032c325b79c60278b194e06e8d0e0f48fc82e1cca41e2c08ffdae0175e9e71f6f250e3a981d8165283a6730c40a128c0fee73b70217bcaed3" },
                { "es-MX", "c4721727de56f97f2f9efec98af38dd8c6c8eeb6391903ad572669f5ea494dd2ac0a075633bd52143d6205ef282f22f5d3359d8d2d891f87c62d51735dd25a65" },
                { "et", "45a65058b68e9df127c528f0c6be11b10427e6764af42ae15cdfa474bc1ad6287867f72becf5f39e2f48f6b59147670feb496a3ddaf44a684492e0e328cc3c66" },
                { "eu", "b30e5427cce95d61248ac5c421293256615e3feae4ba45d228da096ac0aa529ff9f14bb229567794b2dda2ca84050d82626e8e4bf1e4b6516c0b83ddb1012dc9" },
                { "fa", "4ae9ab5c40dc098318b236cd2722a64e4ff0d33742167f92ace5ad384e4def0a42cfd3536c88e2d29d3822db0241988c26c6fcb7ec37509b8642e55e11816e85" },
                { "ff", "4211af188eb08ae6ecdcd3e7d66eb563067cda0c598af7151292c1da7522cbb121b3e64b7af9be9cb69602c9b41f184d843f1bda304d2ad6749436109e73337f" },
                { "fi", "4089ce5d3f660ce3c262516d2b72819952ac6d23cda45dde988dbb6b45571f4e3c7a04f450f5da31eb0c56c2813a45fc7fcf1d9c4fb358e9945d7ef4e3c5d498" },
                { "fr", "5dc06bcb82eb2ec2317f24b9a2c330c803888e277d553ad373e36dba46a92a6ec8839d4e80d654c91ca2448529c8bbd080974ca677c5153c114c09b064438614" },
                { "fur", "7cacea7f2a73bd88004e5fbf045d68bc6ae2ec1a7df79bdcecd82189c918b715c9b0c2e17bbb38b1bbf5103a76917030987d4b0b709426a28db32ef761d67329" },
                { "fy-NL", "9fe82d228feebc528b3c0a6a2860d5cf325316a30a1042cf5a4461f7cd4c6f1e973c69d95874727951b2b20d53cf2f16f92d044ab3397d0a56ecd6721ae7e34f" },
                { "ga-IE", "9c7d73b6fc10b6d1973a4d0fe48215ce883843a68fc88b4626776f6560d08dee53c9947f8acc872125db0da9456e815b72724bda35e507b74cbd0b9e26c89202" },
                { "gd", "1106fd47ebc34de39a7f4569718b003b00c7e217c22c278a8df402841d255a49667b3451e3c4d50cb9eddb00305d4e57afa2808957ae33bf651534a25f041b38" },
                { "gl", "c9524b6746b8120a6093d6cf7c8c5ce1f1da71ab277d4acdaaea9959debc0b14389e21fe965825739feb4c7b9af43ab6f5c1e36ef4e792423cee68cd14030cd1" },
                { "gn", "eee57283936f0c439eed4a1dbf68e5196cdaff7e77cccb8a284c6f8437a8dcffebe46bfaae0d16f9a9b11b4f97c4e48e944591c2eba3c56bcb1186d95130a526" },
                { "gu-IN", "0947a68ce6cf5b9303b2aea2e1cb2c3dc7ff688d02a8c5d8c36800cdb2b3888faefc1168bad090d46bc0511fbdc443c24d397e3bd0d23aeb5eead46057442b0a" },
                { "he", "1a213e5d7db1baf1a213f6fd901307e543cdbd676cddad4d7acacebda005b02821c7a5d494324d83a07f9d7d854fdc58f2f2c6ca72b086b3d6b1f7c92e88d94c" },
                { "hi-IN", "24524a2b11f29d6c9a5b26d81520d9f38af455567d0871682ac93a5920f6b7d16eaef4caf302593325e9698c65cf53ff4a1a74eba0d42d5882e50daf3198f3d5" },
                { "hr", "fc8c9de3e422198243ee348111a8d610d2cc4d966e236b2d5c5c6835bc4c21de3a031e3c298a97d60c1c81cfb6e636f3a45819331c3000e92bf36ae3067db1a4" },
                { "hsb", "76874ea4c436f1297df954fe464f7ee0dee2f7e6643c0faf8bc8a482de51a29745f267f064b6f8f2e8a90230d57a0903ccbbb2dfaaf01addf6df646f3790c479" },
                { "hu", "1543f7c50cb53ae1ae88289634f70bd10cbedc36a602456972b4c5f55eadab22deb7e424ef64dbd1efd9c36b81546ccab7e385dffcc71d74b4c9824502e8fc37" },
                { "hy-AM", "f7e30effa7bad64093c052a4a66a5722172b0cd79132c74e1533a3b6af63478abad217803e1ae34412bdd92839f16ba16b1c98a4e1e429176c42776308500bbb" },
                { "ia", "53e6cfaf685578ac9eee8f7e503957e72001eab90e839d201a3a3ae4ccc338a75dda33ddc6f748a7045fe780b2688e9f399f3b6f382d2d7fc243c823aeca10e9" },
                { "id", "4bd16b9dcb5689425a4e22e67672fdb292337a0ad64c9232946fbba7881fc9ce6464e171ff2d6fe41b5e14be2c842285bd34b1f727ed8aefbe44af6d91a5c292" },
                { "is", "fa955e18e24e614bd26de150ea013ca20d0b35d7b037caf03625d26ebb7c25ac742062535e8cf79358a63f629c8a87910b03650df0e10a5071f1502538cda76c" },
                { "it", "4a8f9005f6173570cf4a5988f5761b8f811492d8f0887136695d48615674299b9d7100b405fb7993a6f53652c356823069895b23986251e0e52093db3af47d52" },
                { "ja", "bddf8081b0ad562ceafa20c458f49fa26150de79e544b966a8c555c6e9de6091a08ea2a48dbf17a40312c0a6846ad8fdcc5f1b26973fd9460eebe48364be3b79" },
                { "ka", "0ca8bb49bd260f14648406a05fdf0e8f507f9fb58654852b1cc5253442d9d95d573c095eddf09121e85f5c49fb16ea93638ed03a7733ef339e489a50ef672e1a" },
                { "kab", "d4e764217566f0c31235c9dd7b11d1054b07741802e744881caca46af9951b98dd6294921540fbb82fe4e614f7e6482ece5eaef5d212cd416d33dabdbe88d32f" },
                { "kk", "b6c3b5e98ae69bff54971ab8ad8ea06ebcf3aee4d1306e2b6d988554b903ed47d0089bc0ceacb2ed4dc22a8838798dcd2727ad94ca32d9c6ffe1a22bfa43be25" },
                { "km", "040eda9471e6dce6ab3a8d6b79b17f8d7480a1fab9e650ff0e85efdf68a7debbb76d5acded46c423f0764d5bd5e95349ec2f8d4eb8618dcbe39c6f7e4dc4ee0d" },
                { "kn", "cc66e763b7f4b70c1c62c694845ae801e8b7eacca5cb6cdcfab6edcdb6f826e4def0c6368ee8efb51118fc71e789b03ea5f7492b7d1eb619124f4613f76c12eb" },
                { "ko", "874c801abfe887414bcbf5a16eeaf4d31d63ab25ef248e9ca69bc58220028e70911e3080cc7214f1c8faeaef871087f855cecc6bedc88f54e5016c1e17873575" },
                { "lij", "01dc42667ba1045d45f62f66d8bf975d5f6e07219e8762e610aea71ae2a4df0d1c4a192c09a10dfe98e9fb367599b325314f4120d8c8a6c5f6efff5cecd0ca06" },
                { "lt", "3e899f58526ad301a0be05f0c11419224d5ff2f92020a070540965c3c3b8adc28602b853b5a92ca9e0a2f9c0a022f582f42b402318f8541d8acbe36617d0d772" },
                { "lv", "974b38e2b95b8fd30646442fcc78d33875244e0e4519f3ddf621fb64ff90b33f37b0175280754ed594f45475250c41615a4e8d2cdc5931708229fe1e996e2f1b" },
                { "mk", "901ddc62e94f93e897923bb0cf3d09f5f07803727ff6e76b8852a3a900d1493596aea97097855e8398c38e064b31988f25d413b3fbd2dde046d5b1ce3aea0ac4" },
                { "mr", "0c7cba427016b93f815c527dd201c8b86e17dffae004195d4bed244db80bf3bfbed7d3722a5b771820105e41a45902e1a946a37cb72f4c202a4611ff415b6408" },
                { "ms", "7102ebbf65fbe337128c8f09d9a13e3d9c95a2c72c3224aaf5567eb25e7ccd8934d2b34655fe1c1985b320a862b11f7f069c05c1bba54e19f93c60e937767540" },
                { "my", "42f0fdd65332391f006062bd6353a5408093ba2ef29d3dabd1aa537d89dd334e149251f4b865d14f13692d78fe77bdf616de341643b8919e020b607d6980585e" },
                { "nb-NO", "4bcd929712a3f6d66d5e872f00b4d4cc2849bb98eb5872606874a367fb05c1edcb0728c94aa35448cfa878c90ee62a2e69e59be3c66bf6cf49ce889ae0eaf933" },
                { "ne-NP", "b4bec5e1226a70e2050b8995dd9f8885eeb08f2bf73a1c0b78054df29740e3474cddd08c12af2da2382349d338b020d9594de5940380731fd46f788598b1d039" },
                { "nl", "db80778e3ab4ff63244d039673ee4ea8d2f4a3b729c3be481834064091e8962e3e53b242feb37936b8ec48ed170fab69c51bf1e5b205f233bd0b6fc6a08e5e63" },
                { "nn-NO", "6d0b3e6772cda3d30ee7f9be2a3a07615c4c61c299a89c69929f6942846a157cf065320c39cae00db568f1cbf61d651bc71e2c5e9258d6dca82fa878eaad6518" },
                { "oc", "ea0d0243bae9cd7143670f822f0d6f0a342cd5f7c6c09e719ed079a799932957124e96a778cd275bd4c87f73ff3e99f6eb870b55425cb488a576829654ba730b" },
                { "pa-IN", "d91f4243f7a059e4ea2a091eabff33ea5f92457a3fff8d6eacc7b3598dace5de06e0d502af26f09a5c055b55cdca665cb979c44c74a10dd9f16da788c71602a0" },
                { "pl", "1e8eb21f6c47341f1a1bd774db8b8e2aefa959ddde305328d800b81dcf83c3c6d3fc7d2165692f8daca18c98b2c23dd9ea3ccdb45504e0d9d01c41eb27223dc8" },
                { "pt-BR", "08d3df4bd25794fe2fc2a4ca059b4c353cad6d496a9a290a43ceeaa9812cd650dda97cecf286f0642daf6bc79f95b059e06c949ca789edc9890346acb6b586a6" },
                { "pt-PT", "83aa2d67ac65cf04c62e08f9ee13d733448ebc77f570999732700f445262d2fd9951ea4d9911e2c62111443dc0f00613d034e276d010c93421bd82fc6cca0970" },
                { "rm", "97b4331a75adeea2d96f9ccff52e4e47984153849c2d702756ce4745f843d0a4700b9cc723fe7b1407b6b6532c06ec423046e9e931acdccc491b4d3ac21b9a5a" },
                { "ro", "68706b85491d1e28b35b6d8bc18ceb3aa338cdde93dc8e406a45b639132d37e1d4e2d6f024bbc1f6f679ea8e360e17af23458e60aeacabca96de579072e294ce" },
                { "ru", "10137f34b5688ec1ac97b0bbb642779a604152fa316fc0c2a9d84193aa859b7f8ebb66766afff324e97789753f18e39a37713748e3afb35cd2d8354328025192" },
                { "sat", "2757ea21fdd40102a50cc69842f2349cbf8ffe46b7ae99508ab0ef53719bd879de43663dc807e904f71f8ab6d9ad391f44b8a62b3ea33d8c96ed51d06652fb96" },
                { "sc", "d7acc16e9b10c55ea7d2034e98636ff931bdb2cbd6d28200c00f1f0868c1ae6f4157a760addec1f86a75523377ba428ee02b30b3671242443e5dd4751ed985c0" },
                { "sco", "0a7ccd304ecd8dc92a74935aa92acdbdf7114197533cb851e78e01fc25ed763c3928086f64cc2959b4fcea73c19bb4ea70165428734e6c8bb42f93c48f3005a3" },
                { "si", "765a75889412c71b48b3acd1d4426b58bedcf94e4baee9e81b1718e3a333cd991010c293b823725134bee9c84c21bd1bdf89d47dd6a461dd7fcfe02a0dfc1375" },
                { "sk", "e8602327ea8aa1d82e2d4954ab9253fff9733a551d12fdc6ad84d69bfa78aded7609b3d773db2b8f80a8278772ba70fc1bec66fd28149f27c3fa4e8e3a85fa1e" },
                { "skr", "23eefb520b0ec364359c02e2f3d05bb2a0735f7790d994d3f169ba1b7136c5f51a168da607c2e94af1dd708d5f44f5266304d8964028c6021caef9bf3a69a16b" },
                { "sl", "9277422742e4b1d6ec2e1cdad39699097a5266b69b8774d692c37ae7cf9cc76996b2b01c110b848ac45a092ddfecf80b60abdcba343dad8da8e7055f6409505a" },
                { "son", "671965404b274149a775b7e52a9160d48e50e661efc153e46560008e179e50bcdae129c6180ba61bea55165b2b66f7ffb4c3a1272a092b05593106dee2223013" },
                { "sq", "b2e7ff6d9e3e7ab7ec0c029b7c1f7498bbdf0b9ec8c6ab824b134e8401e65cc639ae8086de1572380c5270ef92d0f57c6dd68f3dda9fdb95d8cd96b636a2496a" },
                { "sr", "31eaf6f73b4d8f3d248aeafe52118d169823ac09ce99fb8ecab95ed95ab2eaed376e0ba4a6701b918f2ab2ad3e57bf12dc06371d8c3d8cdaa0557fef9d4a59c2" },
                { "sv-SE", "07e400fc1af71d4b00ca3709caee53c48e434d3535be984c7edadc39a90f6d0e65fbf106092f92f2ba4d08d447158a82cb7eaf10db581d07b70a6ca25a9d1f6b" },
                { "szl", "16bcd7f59245f0faf5f5083e22a53aab315545403fafff84a4627ae3342dc28ce3b4e7fef62a6678112116a4004c26bf8d8ecff8040ecc17d7bc3e44c20c19bb" },
                { "ta", "b9ab46fc7253c15c8be7783f8b3c815b45fb365e05720040a779ca4644d746e56473432a045583e55b7ecc19374577259bc62d552443c7ddb2be97c4a15cec19" },
                { "te", "3462a4ca8d463375cad6c32d1c7f9f345e097331eb4d30e65879b4d130aa4494a7b72def59ebef36bba14bec77bde49dab827a916e9b40faca3f2d53fb84f926" },
                { "tg", "b0ff9b5291f47de03ad8d5c9fd6ced7b5a16cf6fcd6cfcc599befa529a8911242ed0249787aceee8c775b183f4e093d413bf69c8808fa7a4ae7015ac087e427f" },
                { "th", "0705ed93afb83c571e8abfacc1ccecab74e604bd4cce592fed220be7ad9aab9372eef87d11fe65c9b57a8cc865f8314bf2d51e515c2b38671322538ae9ddcb64" },
                { "tl", "286c858bedceffc732eba7c51923ddca8ce2a884adeee5b47986e4a3d9ed7722171b1b05c379c3d38fb5f62afc5fb6c81dbae5159506d1b4d105b79d134b54f1" },
                { "tr", "e269757851ef5e230c0535d5497a4e3798305f5274510c1bdf1e546e8e908eb61bfc1cfd8713a35558258b95cf43383ec6cb91402d5b191b102773f09c2f3d6b" },
                { "trs", "f42cc17e20c539e2f8c13e1b1c22878077ee3794ab6cddfbbbbdb97e11209e46b0fbce49df50617d5cb6ce458ee2842c86372e875136f6f887efe8c9b98ba2b1" },
                { "uk", "a2b558ee6b442ec8ba6c364cef1a83181fa2dccc31c0c72ee39297c0d5897fc00c9e362c80e2134167f404168aebd4f54d8bbcf6368de1c6360f8cfe6557dd59" },
                { "ur", "465b238b7083687d66a55cb3b533b577323d6826995a27abb359ae9f0740b0730d4f50d556c0495e5219607ad1c1864474709c7b53bec91d7200bb6e2100a0a1" },
                { "uz", "5b14f28ac78b9bb2537255b0e20d1c91c0da59ffdefccec44eed34a6b8072586fc1a5d365595958911a65895a23ece5426743756288c7926991010acbdbdf5cd" },
                { "vi", "b88de9f4c0607e0568323b94b2f4dfa80f2350283edb7370ab50b918a3a4f322521e7f778a05f1f19a04a2a34e7a02316f3a4e8599ec8c86a9afdabc0b361dca" },
                { "xh", "30a22caf880085605d6810840821d113a8927b3deb48a552c5b7f327bc1e96c64191c4158383bda11fdae18a51c5f02c9ae695244d6a6da9cac6abad80b08b47" },
                { "zh-CN", "2ff12bba8f629d604db8340044d10693a206dbb1af03a5cfd584d2e727a3781cb25343cea224ac5d35368786289761aaf1afe556b84f7986fe27840987be95be" },
                { "zh-TW", "acde71b8dd4adf607a15f09017b5e353514739ac44736f289762cc55a41324b406b34c0abe7030157cd1dc8241734153a717f35cdb57d6e114ecd0f41190a2c5" }
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
            const string knownVersion = "141.0.3";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
                return null;
            }
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
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
                // failure occurred
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
        /// language code for the Firefox ESR version
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
