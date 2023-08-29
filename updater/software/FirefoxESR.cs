/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/firefox/releases/102.15.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "0efde29f174a12bff3d03f9277c9a22dcb06fc7e9644a07e5b1f524961fc768323dfea90adffe267c9d8b4e6d563296896ccc967bcab4dfe6862f183367f8348" },
                { "af", "662167351320816d04ab9ab394d50277c476f7d670c2a0b5724410389ea744825b632781634606d60bf490fbe6a7506b155b1027d94bca7ca8fd8829d02ad11e" },
                { "an", "ec280511a997bd5df46639078fbf41762275a31f3f2e7c89601c58cdeb556d38d38f2b54b75226c888176077e43c94be7b35f79f8a00ce55e49ae5d3ea2dc8b5" },
                { "ar", "054710a06032bd02cc189f18351a485c29973f53f227d24af40273ebad2e40a29fccc4751af9bbd18d1ea506b236a4115bf151d34c858b73153e564e09219c13" },
                { "ast", "11eca7217ffa423f70b9bd81adeeb586794654f9f1b64762e79cc7489ac5ab04622392160b1339835efa3ea86a9c2d37563454a141f34f1c4943fc66ab89c2cb" },
                { "az", "97526e90d6dcff35e5e5800b7ad01996f56f90a961adcafa2fc7078c5235e9d7f60dea4e146569ed641591756a278589297d1dde214310091b7ef1808cd284f7" },
                { "be", "31c322336bd7c5a9ba6e2c66ac61bc088e910a7801f2fba9f1cd63de26a37e21a6feb52b0868ae12c062f0d554203d19d4df11d2a8a6b0d636c9198430ba540b" },
                { "bg", "750c6eadec89b69abfb2e196834473f8c0d0aab2f62860640a88e05f8f1ff11cbc7262ad7e7de2cfd4fc17a825b43bfda3fc8368b2fadbe6dd1b94854a36d0a4" },
                { "bn", "d725a3f8265dd5108d08c7f3874cff20019eecc24678e05547f2c97714450f5cc91bf7ddadb54dcf018e3bcf76f99d3c5507f5689fcd37747133eb48887c2e33" },
                { "br", "a11a054ba318418a56ff3002f4145e4e9c0f4b7de3f9177451cacae8c465c57945f079a6c69f8f004173d0c54aa89033687558aaaa5c2d3981f469b4086cb12e" },
                { "bs", "efdba87bed2ad1180124e24dd9d5c1ff38a4ebafceb4c1f4a6ef8a2fc40e1157aef1d25947429b826b6d4dabe75782ff672a4d738660c46dbdd07e0e5db74112" },
                { "ca", "dd27d700869aaa041d601803e2b7281ec9df9c571819a6d2ab9a4f49737660bfa8eb65c402b2e52c6a322ba11ba8e68ff79235dcaa26dd53c4e90862c0e9dfc6" },
                { "cak", "d727b9ffc4814fa7f6343d7c898cd89999a4aa1eac844e91d332b5b15e4f0c78962fe2dca1a86d21e99c003a98c68f3f53bf9e5fac57a889ff2a189288cd947e" },
                { "cs", "033513366129b17e6d95378ee2c13612e6d587d5c1a2d8f5dd5bc4d3d80167a2014e4b79d6a2d767e9c6fc23d0169c694a55c679f45aa6777a331de1d1ce5313" },
                { "cy", "ba82ccd7a700bd0e135fc4bbd66795fabce56ef95b1f2559e2b6fb8ff00b2a52911c9ff72f3e8187dcf22f4b1cd82f707c181a35fddb407009e6d1163317d580" },
                { "da", "1c0ac4afaf14d4414d3a14ac657cdffbd3d408694944b3e547de595394c92844414f047797ac6be8f8147f2b61ec43ed44f1d717c6c9706c0a973e6250297366" },
                { "de", "61ac5e60ac5333a2f4f61db299f9365b5a235b8b7b7f9bf590512c9ed6a19fef0639764fae8e904a284b598240ed16e26fb1bebc375d288e6f71db7b3f6b6b39" },
                { "dsb", "97de8a2a3844bff90e02ae128083dc5cafc52a7b617a67beff20ab0bcbe4d169de550315c263e0f0c99710d2dcce3c500d895aaddfa216a0cf26abc5030da84f" },
                { "el", "2d0e0452fd5b9061a174a5c7684236f317f29fc7bc181988c98b0c8a2badf3a90d0038972bdacd5d23559524321de0d93b8c225491d4f10026759a1775f47ef4" },
                { "en-CA", "0df610bd4a57654350aa2f14584fba50f50a071497e539d0f31bb5a513c0d3f0b47dade662458b4a03ca33ad2c5ac424b9c541b9e8d66eee2947dfbd3fd57831" },
                { "en-GB", "4d00457abc629a3a2b1dd397ff40463e19533f9e1cf51ea68394da340ad348a013b3d485f340015035ed9ddfd34f132a6bbf3d7d4bc83edae0329191b1adde50" },
                { "en-US", "274fe6a2b086544e0cadacb771812177033f540fb5b0169522be3c2bc4428a0e32153e667dc9e48722210bf577af44563d436c3ceafb09dd8cdf48715b1126ab" },
                { "eo", "c95858a7ccc06a8cc198a9a150c2b77d6a8e1b959329b5ad69ceccb8de3f4594ea0791fee373f9e79cd7647a61fd754b77f39352faef6127cd87edab171061fe" },
                { "es-AR", "cc2053deee2d9e9ec8f7b084a1a843d590324319ad3d591b8fe743483eedb538710c797f1caf282eb3f59a5776a1073223dd46a7a4ade3edc9bb81feb032f533" },
                { "es-CL", "4355b97ff33fee81e0f02ba3d5e7480008f23a63cc02ecb2111ef130b2fdd0ce381f4a6d8b3db613c9a28af916599851bed4c21a308d4ff8406907c4786872a4" },
                { "es-ES", "6fc08f4263b1aa818d95ae56fbf154a44fe436ee78a81091c4cdfee4b21a6996632160119e565e101f0375f2fdb0d5eb6e0476100037969cc5d63a122b8d97fb" },
                { "es-MX", "457ad892a132025247132bb202af306b35106cc09297909d8f4e2a4862c226dbff5f3c14a54024eec557f066d42f6b87b785666cbb62d20de1976749aa3f6bff" },
                { "et", "355ac4bc52ed3eb8d1264b6baa9001a861a8a9cac5c46ef97ec462f7e5766a1e8eda45f0d0367954a8073d92a83896fd734ea42861e0381e5b30fe38fed64551" },
                { "eu", "89feca451a8c0cfa28c5feb98df44df81ed12ea535d2633495dcd0bd600bee18892c4318f7e43e438fc6dc5ee3f8a5588ad177cb406944530cd6ea23499bf573" },
                { "fa", "525f1bedccab3319dd47e7cf8b55f9b473349c285c4d5e7d6c694c1ca1eb3f4f8397ca8ba5ac83e104ec3663a72905b74b67d0b02f192b6af997d8d7a588d65f" },
                { "ff", "6664765219e6752bc56c4f397316d179b2e371378263295ac4edfab4f13ec79ddc76814621f465002d6c9b63ed906ecd9733020ff30cf6eb2c2c86937069f8ac" },
                { "fi", "acb3bd3ec1cac440c344197ca508151a1d7ecae39f2779de0796959b67980ac36e81b7741e830bb7ad71b6ec9aebe7ce5f412d0794d0bfd39fc93e1d6edd78c9" },
                { "fr", "e3b73ce2486b9aba5311c44f397307b1932d2c5ee843c1130cfddbf5e969dc0cc6b75029b380c88e92ae777eb8ee13297d6d785b37e0654e95735c4ffbe9ef18" },
                { "fy-NL", "f6252eac0cd785de18294e06e6af797a135211cf1948784bbd61fe49b21019fdbcaf596f41bfb618d376c26e686f9ec407e526c3bedb18e76669496304b1d6bc" },
                { "ga-IE", "b49dc0b3d1521ffb92ac24a3b9a932a11db29aa96278c215eedf2f1994e69277bb2301514db2bf7b0f6bef939fdcc2ce65b6aaa2d8558411753ef7c64d971bcf" },
                { "gd", "67e99e54315ab2301cd31dcfcf3e240e98f169c2cb5106b2f2bdf5f63b0e041dde050b8d899a5235ac2537de9ae768e302a7b352941a49db968117f1900c26b5" },
                { "gl", "057f2dac58b5d0540df1b7174307dfdb493006d4496cb675d5e10361a81136c95016f7858f95891d93d25d4ba85c149c60250f495b9bfe2f50b23429b3ba17f8" },
                { "gn", "06b03d36acb76731d4d26670a6992d567cdf50ebf19b93370c70469f6db66c178f34da42bcfd72ea880cd1c1c533cc5a6741bb13c54373c6c1d1490e0bf65744" },
                { "gu-IN", "2f727040ba1dab9b7d86702ea06f180de49e9026315e770a542099ac3d220ce57c1c7761235466e4c2686221e0a93267335420663929f3a7733323b89ed0535b" },
                { "he", "22b9f9cd857372fdec676f63026518acb3fa1bdba81ee9a1b51aa0a5cf289058181f6f6f8949a7f244ddb29b03a85fef725c006360d5f63013c72d3d034a2649" },
                { "hi-IN", "f351bb0db0fa6821f9e66c40642ba5795fb60f2fe0cb4dcabf7333a2aef11e216ca366b2be3ef9eef7e01729c8c2eacca2a91c13d43aa58238d37eed38de1b3d" },
                { "hr", "6271708c01c4bdabeccbdbe6b98eb246798460cb00d059e646f005e9663a8dbcf31c4270b67a6a3ae832c819e41481d62282a5595b000072b00ca880e3eddb85" },
                { "hsb", "39b0ef8b4ead475bd405783ce2a3b3c16aa43487c5cc7c1ba934d98b27d798701f4ec508b925b208de6fc2442c7901d1799d3e018b385127741e6cb0978f78da" },
                { "hu", "9410160c27ebf10a4ead6dd6a04e28d36d9186d9d5d337cf6cafc67ddc2365a75d40b8c11f0ec7f8270feaee1e26403023adde1fe3603cb2d45ca282c8540764" },
                { "hy-AM", "cac1f4bcbf94160b74d9d8f3c60271d620318379fa014d1af1f4698933c20270b0ea0c0589d7ca777568e05cd30d1d1e72277eab00668932ca4f3643ccfed209" },
                { "ia", "dcc5ae035c04441e2685f237d5b34fcec12bce73d37cdbbb62daf6984f8a9eda428cc91de4894336f79249d3f9b8daf494b141aa1210acfd0f04058e77ee6860" },
                { "id", "2c0ee7fd1cd38f3454660a5a54671869923838bf87b42cd7c930a798647911623ba4f8aa4477e56e98ccda2db0b50e12ebd9a83d29969c3c5d51079180e4ffa3" },
                { "is", "b22ff894e66060b3f3263e312b66ef04a4b4a051b0f978d41866f525fb541969a8a909bb01fec46291aeec5cb8753dede96225b83c0e33e913b4ee4fe30eb8da" },
                { "it", "d73710efe2efa0daa5b16dca5192efa1b71ca75505ff54ea9c082d7c07a087219d4f8ae5d291560cdca837109ea0d5ef4cc70b64b28a75296a90f3df5ae9c331" },
                { "ja", "a998f26ea23484e4707ba8e35e1f87072eaaabd170ec866c13d309f05844952c18b36ddee064338446071c9e29ae8bfb1e4cdf93ef491d3165ea7372b3f709d0" },
                { "ka", "7b57faa0885711afda02a8ad0e41ab22787eaf390bbf62389165b1c3bee7f9a60e243c623b28d1e53096b5d71641f8550fcc9d4a3c81bc0c279f1eaaa8e94e0c" },
                { "kab", "67a72043328aec7e6827609ff94bf4222494476d9e4cf9eec4b5552800242c014f0e996c373d6ab782e3580312ac3a06c8c5c47f1447ec99a20d52085afbf866" },
                { "kk", "7655e70536526b15b64f89fe2271ceb51f6d6fadabb82b16e12969a78f2b08dad94cbfe4e901c17ad331dc00f1f36691493cf352167e863e222dbe3c96755291" },
                { "km", "4d0b961361a5a827d292b8631fce9ec064754ca7f9796caca8976e8fab251811e8f4a88a6f5a2eb94852b2e4342931a5defb00a6de0eb47146d571192c105401" },
                { "kn", "77c02ed3527173e539d69954922a670f15a2a87f460d68c3f9ab000e679453071616e3962f9e0e975bb244af2d343e93050e9e0bea057378ad5a3bae75b44c8a" },
                { "ko", "143adb2dedd2f4d559a761dd2666397c5eb912b24de2f170dec97c4ac4a7828c8349e80518a32179481e9a053d0a366065acae950ab4891049b51064c45b36aa" },
                { "lij", "70a3c0668f01f807a1ff3f56db8e21487239d44570c2432fc5b85de24de2e806b4fb36d8396d336d5f3b6e411eaee9299109ee995deec9ca2faf8a527cf31165" },
                { "lt", "b824c5a2a250a06ae06f046b47838d6986e22ed36d91d1674551264435920a5b2fd72dcf87873383a3be434911d5de94d928742f517eb36eae70adfc01181c72" },
                { "lv", "b0a0e0f14d14159a52d41b948e05fdd4f71b9ce94fa4a32ff7111eb7db9468ab9ee182af7ed36387be044515736ad078841d1e4fed014cc74118d6b9acec66b8" },
                { "mk", "4da9e51410d5f18ecfa59f91a9b6a3acdbb95de5ca3d0e203d81c5575c24940c2bd0c0c1a459fd4dff676c1c75e2ffe5ecc5534c1748a6eeeb7bacd49d559e1c" },
                { "mr", "b4adb8c578eef44559411acf889712ea6c919b08f0a22f4c77591bb2355d8bee00727ef38ed2308390e072eada9cae12d10891848d54e8d56181865360a324d6" },
                { "ms", "6aed87e0867b9d07fd7f98200af3e6756ee0fbe89b39f585ec614a8b021eb3894d75847807357c700f0872020120e3f2803ac7a05e6d67661d3899f2b6298f97" },
                { "my", "fc35b6e5292d23af9b3ce06d5c5cc9d22f020069478657d77ac3789f9f78c17a30aed42a0893a5973ffdc56a295bcd8d583244c99152d27a9004874da9d69adf" },
                { "nb-NO", "e81f7d095bde328b65741eaaeae1e8ddde8ebd09b40ac726e81c78babad4af832cca2f2146f02d6b378e1abdc37957e350ff9d0759f927dfd9de8e49933bc395" },
                { "ne-NP", "c57ba6670fe811acdd5a3f90b96832ae6b44ea2f0e0d5e3f18e7d1033e53c1102a42818a2ffae6d2a68e1e42232118ce2d699dc37c95e1268ed9edeb05fe4a11" },
                { "nl", "135cd581e60f1af525d2f57841ffdbd5cc5d011b966efe225e4b6dc9aa8e0595ab6ef7769b89d44f307465b784223becea433c2ca260fec8da7583efbeaaf276" },
                { "nn-NO", "a3938b5edd053e42b563ec6db8c9f631a4bb6de13cf4c5d76e245b828176f8015d870dd95317c81bdaa94ae244889b1e47275754af1e02c3133ea66eae09d249" },
                { "oc", "dbd0c44df7bc4b085a8f3e9a5ea34406d0ea6360ef63b439dc4875106257156556eefb1a1954d1900c80d7d15cff4d4e412cc189bbeb050ac4de929638200ea2" },
                { "pa-IN", "60237c047ed89909a5b876009a6c7338105ea748cc860b2a66aebbfdb88afca35e2e74d3bc7126b77fe40d8dddfd842843d37b9ce6dd38c6dae536f9728f010f" },
                { "pl", "d0525a232bd5db38af7077bc75add4ade757de9d2ba295bf262529588c7a4e719f39887209f0d7f834cad3d84472b51d433efddd2b5e127e111819903d29c273" },
                { "pt-BR", "874e5f385f8a45be2b360baefda47fb93f9a2dc40c0e059fd64c56ed3e36f1dd2b94fc60ae47c002e0e69f3886955e85dbff2b07dc408720ca5e1380b8acaad5" },
                { "pt-PT", "1cfb6ec3d101e27503f5397f1ba79d2b0b4e58d3a03d75b6e4cb4f6edad1286deaa9a96d1d9e4cb18e7100865ba6241290a19cb19334584071eddd2e00c905d4" },
                { "rm", "c7d11b5252fa4a86728b57e5f29252ec91aaf3972a85a05f9014711cecde8299656ac15a1318587337f305a3413b42ad55338f2872c59bb34a9819d781daef97" },
                { "ro", "9b25f77b99f1e5112512223f753632dec5ac9f8e63a8a288676620a32a4aff7512f3423f7f83a0c9c80b4cce392a36e2f92eec35b55add7c6d5efad265f396e7" },
                { "ru", "c3f4077771ae3eeeaa1397fb6b93b79c90f907ac14127f55f70e5e5b51d58631424fee378b56931602bf0d82ec9c502167b87451d3ef10a0cfc85ad92e6c5cb5" },
                { "sco", "60efb8cb468624bbb95922e51b4d253d0477998cd9515ce782e28be36b9b098cae9bee0c94426ff607e5f995bb3fb4ce7f6e39389a74ae0c8e1442ba2b540cae" },
                { "si", "70c046bb649954011a6476437d43298b7ab707f10787d5711c51880fce8fa38c337d1c09fa44925c52049e914397f48c88615caf5c2293bb95db8035d5798e8c" },
                { "sk", "25e01ac40efdbcc78809746b9b3c5b1b1c999347981d8a0436831c0403ca50c92dabbd37fc7228f35de29d8f32815d18ca517d1ce1ec23ee22624800252b6f7e" },
                { "sl", "532d08b4375f31c7cb0e3e405edb75df903c9304404612100aaa88ab1474a4e7683e05e622db45d4d9f0b484aa87d8e36fb87eacec0d38e45ff3ad6aefe8d557" },
                { "son", "ba09cd6847c4843e3c8b1728cd5ee2eedea1d92d568667cc7b2c6e5aa6e0d7ae5650a2d99edd4f3ff54d52d83e1abcf4a724a33ca43afaa3184407255f521b73" },
                { "sq", "6228b331d7665652d5c31676cb38fe741771310b3ed67a2a7973589f5a18d896802c349d0db28d0757f851f7ec26a8ecd540b99488c6a21551442a5db223b7b7" },
                { "sr", "a3a0721f97dab2e48f596daa66479aed98e9b9561e3cc5b3d40ee039c44cde17c821c7b9fcc6d6ddd3431bbf2fc07f83c55fe5f7b0ab4651ead46f2cae0763ff" },
                { "sv-SE", "a85700280dac10b46080d2af852c4912f9076da5009eccfe90e64dc1f45d3c83b64f08af114b552e85d7bcde8b1218634481d007b8d1a52bd7b99617dd931ee4" },
                { "szl", "09e38daaaeb097e44f83bb079a5a85f70447edba3d8e0bc53ec45077500f040a35ff4c0793ee35ca2c926dedea99e001b251a0537407361c097269da0960dd97" },
                { "ta", "cf035c2d42eaf9489e5eeb51f32fd66cf40c7e7e11f3408ad5997ee248ed6c296914cbe5bcef047e189e46ed8dcaa6ac844e0786f6070a9654b1db9936e3f6af" },
                { "te", "36b4e7f6953212580ecaf73f5e630ae3c4fdeb53dca4c07fb8fed4a101718e16ea99609f712bf93f83c33fc15d656048d9b5b2a5c9748ac20bafe944ecbb269a" },
                { "th", "64e3212086f106abc66f22d25c266aecebaa8a591661b3cad6bce643cdc76dbe13b87920d2c017b1705a5a5742160e16996921b17b289b033d8629d93e63d767" },
                { "tl", "5fea5543f1b77a251b2c9dca88e0a2e7637a449c8fef211ba6d5be762285b155e28b20a31b6ecf7bf161198579cd6ea46e55cfa0d89e6936cbb3026695af5b7f" },
                { "tr", "6ffbc10aac7051201ca72a582b61b5f5698e5ae68ba6c88c337cb5cd70fa0b40158b9226ac8d9a8c5a7555d1e0dcb6a1d7e8f80d057b96250da5baf4fb9cb6a3" },
                { "trs", "299b8954c28610d9010c4248d9cff329ae390f70f431ad37b991e24ec79c370279dd7f42d3bca849fec771236dad02ee43d3a39db52a4404ad09ab2e1ae358e0" },
                { "uk", "55abca419f8ec12d18c012f06ece9bf05721daf48a0271d08668e6b4975c039f5f74068d8610feb1aad3e620add2fd564096f076a6465f65de89d8d7ff04a5b6" },
                { "ur", "3d2637b9b6afbef390f74ce133880833a990551ae2a8584f2221cbafc6cb19ff159038d74677aa0570c3b0cecdd1bb60907d8df2e26b820fa747fb986c91e8ac" },
                { "uz", "2ffbbb31c4094ceb1dfce99a89462425cef3bdced6df818acb641552459e5381b9023861f28d95c5bb363a293ba931c6f1f77687f16b68918545bde639b4f6dd" },
                { "vi", "38f52552ae7aaf194fb466f3f662fe22926cb84d0f4732663ec0d167f8e04f3b2f9d9569a84a3eddac2988494cb33b215c4decb9c631e4f23f360b22cd6d5b3a" },
                { "xh", "d1ac63dc8feca140914f8952255a1bb880e2c1c9392dd7fbce9742154ebf8f88d134303be9f42e98d955ad4930cc2ce1f54d8d93789bb6ddf16202d397928e33" },
                { "zh-CN", "37228e07c9392d25551f66085a3b5e251156b9fccad9323746f1bf3c6523cd80270f8cd5ec3da4b03e877cf544b4b42eb5cef48e0e46ec9c80ef3247df390439" },
                { "zh-TW", "784b1324a9d34d216498022645b73b0bc89c6d2e4009016e7adc07560502e03434e05c66f6e7c4a3018d8c20776fbdb750fb6a1f539f20510afcd627f911d882" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.15.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "a56ab674390cd7858e9ea65cb411c9fb8dbd5f10c38da19cdfa65c53968446b66bd1ad3378fa570388e1169f0aee65f59b687354ad25bb3420290a7b84ff0d45" },
                { "af", "df883fb8f7ba14a9b69f2cd2d9f61604920e566399feeb72167b20fe5121f4191a2956195a9ac6e76f0d00eb0acefb2ea60762407e85c397c23b56c44cb94fcb" },
                { "an", "5bf1c7f393f5e68459574432fc6798e041cf36e201aeb7ee2aea1c777b28ee7c9ad7e522885aa41dfbf43a778682f7a590ab0e30ad0af39a7fb6a3fe2254812d" },
                { "ar", "925b93e318ad128c7a2a1f70a5d4235e0a2162759dcbb5f92be2abc6b15d3ac654723c681277755dcc10753eaa6261ed53133d52672c4b064c0010a86c892d27" },
                { "ast", "86acb4b4db9594e1c8243862cf9f51447118e32bb58aede963efefe28e3017acf7ccaa949ecd391fbf67e5faa57cad526b3a710b24ef6d05f54db1a8e6bcbef7" },
                { "az", "e34282b589c929570bf940e28121202cfb67fced563c94723b30b498ecc9a50883e6f31747bd74f03d9df316e2b2c865cf9a84aab753bce68e0c13ae0135a813" },
                { "be", "41a8f93a9964888d28646654e252bbc727c7eb8a0b3dc97d8e7c05bc08112a33cc2d1e8787ca9287868401ab3fef1721e025300acdaa516b39b566d860c92281" },
                { "bg", "09326698212bc35ccd2938a6f6dccbcab0c1affd775d2b008fe30c494de0c83bfaffd61e9c72ad3b98aaa2ecfef04ae801e378e6b01e154bb8b91c18a867309b" },
                { "bn", "93a032b435a1fedc746447cc94632857961d229fb7bd39e7dc02923dc300e4b268c8ea1eea9646d7cc7d68c1188aa29c1f5ea43c53e283c4cf47e69af61fcc6f" },
                { "br", "82c818f692c0a5620004bad4e9a8964a69709c3cccbca076149079ae095422cb6bb7fea46124ddf82f5057f3100fc995621a36af70dbd11dcdd98b3d6ba5f37f" },
                { "bs", "efb87c50085428c70eaae63927fcc8e4ccebede5de5ca9c35135e22813fdc1b4187a26be133e3ed34a616c66c8a56bf9177b1d3010ef9073f5acf28e6cf704f4" },
                { "ca", "9ad982db1d8b3ac2d97b258d78bd1e0b8fab292e17ef59cf55e75b7ef1c7787f2b329e9e67411123cc174936d065a6f0bc5dec6d615ba88bda848213fc78d788" },
                { "cak", "bd9a54057a04fb25a0d61e034368f6622c108943bc4683e8923e38ed25253c75f3b13cfc42b54f34581b11d1b41157f378668efab2f156c5743edd81c146b899" },
                { "cs", "15a3ada1a26648025e8c71e72e4bdd3147fb425c03035121eb2f6eb8625d252a3917a8e112cda5eb32f63a85a5c09ac46f26112a65a65a949eebec15bbbc6514" },
                { "cy", "5ee0b02a28ec488c7f45ff5c320b8b46bc0d3139d14d599c8401cd5be90d60445851ac6ff34948ffa815265d4ee063f8843751f6058af0da9f4267b288867763" },
                { "da", "ae434510a4d542f44460f81ea94f8fd040f0138bd86244616ec6e00ac7f7678cc7378a6c24cd7012d9bf44bcff159ae70f60b71bf7a69ba896a7f76cb5c3d0c3" },
                { "de", "a9b830d4e355361f6269fceba9d5a64ea6ef587a47081d9db4e0df622f950f2eeda4605b27bfb82f0a2930244897f80aebe32db65a3052d8c639cb2c0f38efcc" },
                { "dsb", "f4076d039f8ba7e48c46980d6efceac6d7f5a7ecf303125d6741a8e8396121460c796f23c5407ab944a2fbe0510fc0e4143fafac58f16747ea87923249ec82cc" },
                { "el", "5b16f68a1ff66e41731e9d6c2b70fad57df4194779525a304ed8ab040eca2170445b3031a9309dabef0bcbeb9716dd8b72aa41926376c6e6d7f7b9ed08709406" },
                { "en-CA", "594315bf510e3506c93e1d4349ede1e50e6c89cb1ca34b7b7cd79ecd175ee30e0c3d778be1a77e6ba78ba2bd06c5acbf0f19672b21b85a700f52f4eb8e3caac4" },
                { "en-GB", "13d7b20bba23be8b16e1bda30344008d78d73af0bbb2505c2167e3493314ccba01b83c39b00f16da210ae53ffaa30e7a3c1b3451d2c2499d8c6b9711ac095dad" },
                { "en-US", "767a5f6fc52d3b8fb06eaa90f718e878690ea4066c1acfc37375ca9927b0209afd582620afedccf17444d07973534e546cc76d5970514065a86889182f88f300" },
                { "eo", "84ebe0e19fbc66180c6750e51830da318b262415f4df1f464ee762a7fce07b5ca72cbbb13acb34673ce2ad15ff4d6f28ebdfd573d9a7b050e1af0098208e5269" },
                { "es-AR", "7335be6b54d9b0769b9196a861fc7513220f1f06b20a3c6c4aa1c2a84a744e3d0ab67be0c07a326548f8db6ad0fd99761e8a3ba5112bb540957f17ccec1de392" },
                { "es-CL", "a16a2bba0b1eabfb0d421906bcf31b76ef0b7cc2f8318492e0800668aee6ce5ae9a50e22d68e8ced4ddc410a0b7d560f2da6176389116dd0196e24f653cbe3d7" },
                { "es-ES", "14eef3965317bc1176b6498c3291161a90dbb8afef21006d016e4cdc2a7a27eb75ad9391d0a30fefc1fa709e782923580b319d1e8aff17782cb36263fc746f05" },
                { "es-MX", "64fa7bc724a9619a14a5550bf023f457258e263db3262322cdb80fca9d8b05d30eb84a5aa8057eec167eb5df61299be910eb0f764b91572f4f88bdcb66372e00" },
                { "et", "796d0c1585f4d5cc1c2c970019ecda5e2345bcc51e050ae69bd2db95ebde7e4c802880dd45344b8305230c9114478881b2e878f9e1a6ca875241a33f22d0e6d2" },
                { "eu", "62ce4d462c6fe3514630bf8e8ecc2d58f6eff8076e4a7f1512eda4a61b655eafd918688fb4e45fd1582d8c9243b9af9a575bf672d257158c8abd6d395567da97" },
                { "fa", "7cfca0807e028ab51311cd2b9a9371edfda34cda696e89b8e80c46b68e7affaf9f3e1451deb1d7da82a824ac69210381ab1cb6c13b59b00e1ac2b45db84383fd" },
                { "ff", "4a1458006e1881a65490d87fa5e26ba618cfa26bc202882291178bf52a1f25c21943fb6efa8b4f04b88ac18d5bcbcf4438f7f844838c2d3a1607dc947ec9d8c1" },
                { "fi", "7f9c1cb9603b0a7e88f60926f0943a1c27544047682903ff2a7f258e1ecd88a921f0ef9c35bd63acbe026834de747899c02c06d8de88ac4a40deb44dc1bc2654" },
                { "fr", "1db381cb4859d011d7bf31770154625a46d58dd9b7c50a15d9c2c4dc4d063dcb82b1c8b3bd2c48d85aa8d644059380dae2341330029cb26b90ce2fe11d129af3" },
                { "fy-NL", "7db82ef674a248b8091d9acba1778c6ce4629b25f7b560120cf47fea1a89a197c7c48d79f76bcd3b1745f6e7f634406d57314eac51c874650643588d7e23c860" },
                { "ga-IE", "36cd8e0df21231404de30062e0f045e4c45d25991ca300b604668067a8eddca99802448f32e26f7b18214a4ae3d29a1e93baa91094e090ace8132c1420f39b8f" },
                { "gd", "6da282bf721400b1d8eb4b10412780587013d0569f8f039cb468801b72ba8abdff643c6a10ce6581064181d786ab64f15bbf50bcfc0f0922dacec0517c80a3ec" },
                { "gl", "685af750a8a8140e2efc14aee9cd2ad1859af9022da80b4efe5254916b3b024a7d41db33d77d2f54a5e9dc82ad6b06e9143ce7f2e4c7178f48e4e3e956f94c65" },
                { "gn", "9f01c70aefa9b797b147fd8115c00e95ddf24c24277f9274ae8228d61daec54c640204b9d693cb5f20ad396779b158735e45c97ae8baeeda9bc2ba069aebd501" },
                { "gu-IN", "ad69c93480d54a6dcdaaf7befc1dfa7e4201fa228e75245d62bfbaf152024f812427beb25d06165e31277181b6603e34ba6bef8babeb57c3c450330f94fb6d82" },
                { "he", "77fd63e08b8e64d8f53c367c6fd3c22c53707b7f080f1a8c2883752de61082846bf74bfd5353a83825fe31cfe7d9d387149025a123c941cb61cca1880cf9be0e" },
                { "hi-IN", "3078435c5c58db1ad9c37b36017665b0cb37c672c3c02429dda31403cbe50b7952838bbe0a341fc76c0ad587c3a3af8765400522359510448859e226032acdcf" },
                { "hr", "9a35df78e47840be124d451450ed5643e7c6c6662ce372fb96798dadd3819a8f738a2396b4e35578c2c383369a3c55575b52aff44277f6aef8a67f11771c6c63" },
                { "hsb", "a6207e39e27628c98ca279ef32f1eec9f2ec22aea7cc776f01b51e25baa43a97a8d839b96b67df4912be95598bf4ee70f808487068519604be3666e3428bd1b1" },
                { "hu", "10e25710a79338fdfb8fce8ff29b4d4c92c1d77b01d6e37d2059b6f93368845a150e1d71b9c699214091d865a23635d4b8e214fbf0c0d4d71ebf9b3faffd880f" },
                { "hy-AM", "2512cbadec47a9133f39d532accae95f705b46b2aba697ca3dea8bd1225b5fb9c54d24ed561ec1d6f0ea68ad88b63234b43de55908c28369b6c4c164a69c86d4" },
                { "ia", "ce2d20a045922c410571f243084f95bff24e802a0cfb6fed9df00d3e2490a688d80381584247dfb8843dd4b2399f4e8392c3bdf9ca17c6849776c6d9199f7b43" },
                { "id", "0fbdf74c4445944a121908bda1b75191ce31d8f2b5a12b204ca11a99ace70899546613333428cbdf902ea9e29770000e036380df36d2e02e0d8a1d118f5fb17e" },
                { "is", "0d197c8b80da820cfe6de8c7133eedc20dbbffa052ea37e4b47c41e83edbd0957534441cc6e859312d8e8120aca970e66549be0d1ed5038c13108f393cd4e786" },
                { "it", "cd5467efb7919ef5b3cabc44435a1cd3cb37610f67cd3493ec77b4327d8565a7eb963106e5a0e10566b22b3a2368525338ccf3b7564491471a094e11e95cba4f" },
                { "ja", "b9fbd0ea7d22703f2f944996bf724da408321f6700b3e8a0aaa4b704354f2adc3edfc36157c904a22f62dea5201e4cb52a53f23dfb3ecd11a5fbb0aa446e9fa5" },
                { "ka", "bf43e4bc735826c27eeff274b1eb101a1509fc480f2445ec51becf18969fe4999767190aa65e6ac70a39b3cfb6a6a064a944234360bfa23f472fc52a92f109f2" },
                { "kab", "0dd0f8dde5d2a0b5ecd95259b1855b674e3d630faff47ad6484ba81fbc4bc7c6f6acc437d7aa80623e4c6c2539e73b8dda190c56873812543508c95bdea7d24b" },
                { "kk", "3d61085b3749f410c6d911ddb52f07a91f430b56ae3dbbe4e130ea2a73ad27685bc754338d6d496289f7802a9a44d9824e530cbd6415596767c7b2f5172b2bd4" },
                { "km", "8862fbffd137f667a5ebdc37d8a0e1ddf0f05d2a558eb177a1194d7ec256eb18829a71fe666ff1e5bd5aafbcf80753b183fc42ff8ec5af9731ec78c251edf79a" },
                { "kn", "5e52873b784cde73420529fc818b166226991484a05830421abb8b74d270518976015c17554d6c6b644f143bf6df33f6fd4f6e9ee7c1c6b7da26a483ec4b0869" },
                { "ko", "f77c7db837411372bb1c9e010037b50d80d50c2a5aa997e1c8d77347bd916046de1401982ae52dc6a1933448b41b56cbbc151c7552cd289650ed0368f2109671" },
                { "lij", "e73323f571e70dc9cec3dcce27b48b57c13a9d295b061a021e150e8cec0c24bfd8bc5d2a617c76364fcb43f0d4b91c570117751bee214b7230de319ddba48093" },
                { "lt", "12e25170100f8ad8644da4174e769b45cf067da28731e821fae5dda7547f72c4a8bab80fbf484bdeebcfcc8d991f91e279502ace9089fba6180affe8eef55c61" },
                { "lv", "ffde0ffe9e13f481ebd5e8d2f447a3210a858afb87ad423e84bf5677c2ff0754a41ece998ff8e63ed3ad94bbe02ea9c7fd853bd746a3552d630d09db3c5bfffe" },
                { "mk", "5a7986ead757db9235d9e58d44a36f7a1a6ae6f7e8c93f358d43f60962f961a20d4468e375c47c0d3030f8510fc26886a442d5f459e23ed273696dc4a52ef253" },
                { "mr", "ba263effb5ca4d66d84d4a666a7e25db206f6d68126c6dbed179f44796a93e98dc277f7998a71e686f759cf517470fccb689613def974e7d906300016776b286" },
                { "ms", "d3f5da4e83066a86c0ccf048d7b1e39aea458dcf46aafe290d0c2e05d51541b2aa083e701cb04967d9e2e4cb70221025e013b36046c6d6f76737de5d284a41ff" },
                { "my", "ef6ed534ea50072a35d82fb186002a8fbb281457f3bbb671bdb97bc0ba7eb21ef48cedba8a18950e8c5b1b54fd87cc3f2e785efb692147ed30ae7460b8a151ab" },
                { "nb-NO", "766659ced3c68df361104b54d408bcf870f276222d0370031c4978d42d2742eacae343fb3e58e58be94d8d909fb9242eefd1539361606522fa1f49e5f0b5ff90" },
                { "ne-NP", "286907c5549b5270e50ab6a24e01efd0103e2702c63c69d53d8a61309f93785a85200bbedfdf1a34b4f3e0275554bcb8245589eeed33331ecd85868aecf7394c" },
                { "nl", "20023c4d06f04e1fb2faafde74d00fb0c874deb782d981974fc1ce58d5bf5fa0ce19e21d7c43b25cddfe57fe8f70d689af3874746555aeef69b8f4cbf96bbead" },
                { "nn-NO", "3ffe2d6f42ec97ffe315d5f471e84a9b55d1eeabac88d079b7f9881b8bb72f18c9229e4f9c8e0937152f44f585e72d8a9055e5a57f044b86c21f143823692582" },
                { "oc", "3782a8dcb9cc432bdc264f659e3d2263021d1cb731653cff295afc4d878883d20a3b62f6d5b883e39ce6520289b5724c527afa10703f553d7681354238e5a8e0" },
                { "pa-IN", "2c47af9edef7a2568390e5809615ff618f01aeb87ccbd1ed5e9554be9a8da971aa6d1fe6774915bb406849900260f6f1774232cb92b2938ffcd53e012322bb41" },
                { "pl", "b0ad946b6ae2f6ba49b1343a63d02eeb9e9a50970952b3b796fc19be9b572683f2b30532030a027f99a1fc827ceb9228da079e00a53a2319e17835e2bf73c96c" },
                { "pt-BR", "48487f1a6f1e9134e0e2ecb572fda2227348a6d7dc3139dda9fa19118a5a5aeeccbe42218c1c3f3f2bd93ade3b9334c07ce992674fac542a597cddf55f7d3d05" },
                { "pt-PT", "95cc1b9037776f624ec94389c328dbb65f9d28bf0e958397bcbd8bce9b6df73516c383f3e880a055180c0ff540300582ba4f6406490b3e7263ea04bfe80149bc" },
                { "rm", "2b56d6ef1fa1c8c52993923bacdd0b03359a9d7f7265af78fc7d6e3c15ff03cc6e19828233fc139f69e774929a826862d48448819df7c15494f3d17315d22d2e" },
                { "ro", "06698190e50f46caa608c439d14ff9059f9718866b3b370d711c7795c4abcc44b8b7839b14ac33fbc6a5cf2ca16f3a14924fdb94559e8e62d95717a739aeeb09" },
                { "ru", "6f6a30775f145a9ff453b1537a2884f73422f5c4ba0ed801ca2706dca4f8cf7838701cc3ba446481e9087733cedd7ec1fe92f67ce6922188fa370cae07f67dfe" },
                { "sco", "19449b05452635347cf2fded4f13e4212df33df611647ca9b03e980b1ecf43ac91b760efd1f5e16fc81e8088ea395e07a8d4e396612d4f157da062d155f82445" },
                { "si", "f41fc9dc3144930926e92f427de4fe92f18c41a769cbe1c050828c3b31507f4ab3683bfff407c3544d35340a3141d26c43714be4cac5c722b27dabfab02da64f" },
                { "sk", "d5e304e398be9401f0d67de7cbe152768137cddeb4b173239fc78d04da5b787daae84f27a6ff3a46a91aef946aa4d4d0d96b26138ca0e810c0282d6ddb94c553" },
                { "sl", "ea4b3bef03f7f885b142b6001ec466b33811b069032cc80b91f71cd9e17894cc37d24d6928c231cd10b6ca3f43b1019ca5105340ff5b6d48e2a8c711a4422d21" },
                { "son", "9a1ef9d0fa75a518b4f84836e7745ccced81d3971a59e43653161a22dd4f3b5e7e3dbf5dc07ae0edfc65f8a2ac5098528c3ea5c27dfce73259d48bfb21de0828" },
                { "sq", "d2eab15b843996271a80d3842748b17136d8655bddd198af7a72a0790eec5dd2cc0320081b4918cad3a7132441ea95aae5c8448ceb21dba64c38ae33d7f0050b" },
                { "sr", "f6a5432e3f4cc448cb3c642be0c9f0062904f6fca273c634bb80bd31dc2b0bb7368c370fd27e8429894a49de1ea5eb9dfbe4c5b849df54b80950a602f456e868" },
                { "sv-SE", "288a03f2476efb62fa50425205d3a29b91e6c9ecc8af9521ac5883342c1c240ff7b1d4c8f569a7645465f0ed74e7f789e758cc99ab1d5d596430aedf154571ac" },
                { "szl", "2d8aef16baa5dbb29414891cabda8ccf396e40bb5f8f70f087bcd864da48d21eade4461e27243a68309ef3238769266e33b9306924cb3b7a660c0f6bde48de70" },
                { "ta", "e0c0d231754596ce629ca42c8648c74d67da0f0c1259fe22af354a297ba8fb636a0ca0dc0feb9804567be888659c56bc215f453076f25e38a5b3a118c43eb115" },
                { "te", "cec11e9280b3ffd7ab80fc6e0e417d555a3d69e65ff8fb353bcafa8e6db679b86cdb7e82ee1b045cb220b58f9fe6b9ee9d9d0ae4d132bfd6722c2f4b9c7940a1" },
                { "th", "6ad2be967f1852b6456348da8a9d44b9532a70988b48647561e031a31509e31de6a8efbe8db1e41984f0b0e79da8c5a0d088e2bc338405a891e34955c4d2d568" },
                { "tl", "93866989d943b9f16cc8d400e6c04418fa5958824c861e11b310dd9853abc9eddf2ed960415be4a3a8c89cad9b1c3677572cfc8549a14d12c5353658826e5742" },
                { "tr", "46da8065c31a09b9ca6e8b42bae3e4ddad6b889d4b160a6669b59bba3841cd9d78f54a86c5b2aee8bc5254bf82e70f5b6a1123d012d55e035f34d24684d872ee" },
                { "trs", "48052e2b1f67416431afb733640173cbdd1b43ad057b60384afbb1ba03eed42aecad349a30cd23d5e1cbdbb466e5454e7e5a56721be0cf864dcb4f4117ad7667" },
                { "uk", "17d1ec124c9b261fb070a51b888ad7122339cea6280c2a7d266f6b18b46ff801818f50e89b95995395f28d94eefa3e12a2744077a2ac167bf1d781ce299adcd3" },
                { "ur", "3c3129545f4b7a5128ecfff07877a6830361a080b7947734fbc3aa3c9cb4a721b693230af0f8f6cf8edb96b1dd13a725a1e651c0cb0d0022565b6481c761ecda" },
                { "uz", "d68c375def0cd07d7964f1f270e847a03d3a52f07ae3c7afdd9751e3899e6bc618628d3fb64385daf2e71538971f80c012c8c462b199b013e7459bd2ce418497" },
                { "vi", "ebbc103df23c2a1ea248aaa4da1942d9d1c4bba157ff27c938e6a497d9325ccf1dbbdc710c254892f476a2faa30cf5999655bb88962e2a609285111605068c89" },
                { "xh", "bfbad28703dab65148f6eb99766138f5016b5a89e66b63a9b4903f9bc0da843cd7bfc992ed9a6be06a86fe96ebfee5ac7d45a2db40c8c293925e7a4b65a35130" },
                { "zh-CN", "afada388425b5a73255d04d970a36c166402fd785d759b81a0a2e7c0abeafe8b11c7a73045327e228ddf0f0700f813c32f9ce9a9fdb68db302ed88c397e98be4" },
                { "zh-TW", "ef856629e1a19b96e54b88877d1a0c996b163817fe344b9905e8cf3d4bf14151515012b8135bdc55527fd8e562199808750e5a3e6d1d4925d60d32d420e7a716" }
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
            const string knownVersion = "102.15.0";
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
