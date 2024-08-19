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
using updater.versions;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.1.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.1.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "c25ce023feba8839292778fe6727fe272f7aea9c15564d1dad40a57e86fb95fc6db374c4d5905977ad160f6c8c6c41a0132a7b5158cd44fc44446b30c84e1064" },
                { "af", "5e2bb075ce5b43bbd307a3317d50e3f090b9a6f615387a7dee1b0aab1be74d43ec61baa0ed09f0b92fee1d638f960c46d1357b9e276c0ecada7d0153d427fe93" },
                { "an", "583e424015113e7de2e654e4bc73d6740629f3f8bfce255d6ecdf90f536df338082bf9b37577f7340cea3679fad93489ae06ba4f1e109d88031b58ecc2a1b187" },
                { "ar", "6237f3a9f3b5fe2439dba122ce329ceeacea5a4cb5ad1204c6a3583590469ce491360eefd88d066220042649878816333e40bb645d4e7c712ad1b4b9f5ca7da2" },
                { "ast", "b7fab72fa4a89fb59ab50c8d5e40008e6e31bd80b3758e07663dcdad13bc45e4b51cacb29fd21fb64881156903b152720507a5bdebe0cd36e2d503ef7374bc9b" },
                { "az", "58403886044f0130f888d92e9800a0872290813350e8d018f26d07c4fa7655663e0e47a07b19adcfbf6f9e8d091addccd24059dfd211bfce8139bcaadf379155" },
                { "be", "e71f2aaccc177562e00d108678b205e19ebe5da0764611ba92b27bdaad6e885ea11b5e66467610f5a67ebbb340bdcc81887535adc63a3c2c687bd302bd8e662e" },
                { "bg", "2727474a03dfd5bb212e718ea8511cf8c2887ea35ca33170a6c7e76451ea202d6b39bd51664c61b176281487145e5f45354d4b12d5b6383d10012c245372c11c" },
                { "bn", "4c18ced89167bc8d89cf0816ad09547fd6928f5da29e4ad70cd0c1ccb7e778fd42cda1b26f16bb85f636865bd7ebc895a4589d69a48175d5b1778e196b5ed84d" },
                { "br", "6f9b56e53fc23f25e8a40d214e15a9eea4cc4348526493b61732c3f44d7abfec7ac019d96324cdfe6f621be645f64d3f40f53214318ec435270526a3fb52907d" },
                { "bs", "e3588009c3030ea92aefc6f10b2383f30d9c21e81b19b44573bc48d45b661a21e13ac6f0706f9bf84a99861fd9d9d4e14da46053b576dc714a51bdc08c538153" },
                { "ca", "d0695e382d8e76f4d5fc43b927d2c2f24669cd821e517516ecb925dee0e5a35d789bf02d6908b2803bc070bf953715589980f9aa9e3031de11df18a891eb7f71" },
                { "cak", "3ee2e18327c36ce60ac4098962a68bf50e08e38ce194eaabca4bb5fff710d78d6b13d558983b65930d42f8da0cd5e38ce8ffc36a12d2f3a58518f59342d46883" },
                { "cs", "9046ee7244f9bcb40c4a43350d77032fc69b075622573370cc581e7d6a3e108f273674c11c86a950e9eae521a9ce1bac10fb4a51dd04f52dea100d8fb21445d2" },
                { "cy", "8b47335d128df547052558b2a8bfeb2ddcfd0595f9bbf6570f86043af1ce7fe9fea117c1e5a71815d6263a21a7ee12874c5712ebdb23cb5c38695ed45a8c636f" },
                { "da", "4566687009351747a717d24fe741de53f6d0b8f56ee31632f93a2c70a4bb31b136a309622aaa69c57d28dd1fe46710a0df267ebb71d2d47ef11bd93fcdfd4840" },
                { "de", "dd6f68a79cdc1c78365848ddedf39791bcad51f9081c53225826a57c7d3e38131ef92a72e07284fa9d23bff5a366bcda0b6f792cb69ce7f95839c80772093a0f" },
                { "dsb", "5edc40233bc8918a9666bb57f22c20ea0316c0801a875fa593767c1060831629286c0443bba98489f8ce525688a76f705ef2116af943a8499ab6bc654eca46c3" },
                { "el", "95c936dcb930e5cb25bb67b76154352a89a62f573044d325fc0cb8a2cb487d5c67ad25929ef5938f0974354f65096b774efeb59767bf5d48d2b54edf8f504cb6" },
                { "en-CA", "091fd5b8aad744dbbe56fa67c946147e2b1b3bb72ac81554173675cd59c55a241d0647966b60132f68e44c7045bc48b2723c6fb5127bc2b8f1fded9f97fd1c26" },
                { "en-GB", "c55f15f1b6d7aa0089e38dd170103003a80fb002045904ba2907fed32f5a5afc5ec6b733e05113876a425dd615be46e4e282e5695f940a49100ce8f6c8541843" },
                { "en-US", "7660291c8b09b5de12f6a7a90533a49858e7fee3da19c862a7fb3d6a52f9a0a86b0f7f8c33426930ed5c8fb17b4f9add8eaa1362ca81331f6cae6e88e9e76c09" },
                { "eo", "68f1c6e0a74fc66c06c34a8b61b5c425624a5251b2230d0ded8de14627a85d5766aca31d50d7ae6c1b8b685958b3c38add010e03959655b5dc41f81c4721a393" },
                { "es-AR", "4d37705bdb86d32c80cf3996e585d6491213f00379f47f94872bc8afa1bb0f08ebf4842cb662032984b3312a1cbcbb5f00857e063e43f15be79e4c5ebe3167bd" },
                { "es-CL", "8c5501c5458339f97d741d9eb4828c5daefa85f85d5e034ccaf2e7396e1aa4a2bcdbff1f1b71a9490ad0cec0f0ff782b9117871a52794e3f10e66f42806ed281" },
                { "es-ES", "713720e04ba12ee6e32f5b1196b7de7a361fbd7eb842811157c2c4840d3f50e0808874caaaba3f983c7aad93a5a4ace80cbe5b7262544b13f0b6f32f1636865f" },
                { "es-MX", "e013fb150104c80d2856dc4434761530b60693d015be228737bc5bf32f9f2b55cd26cf8ac42f912f0c930bd58194c0cc249347f47982d5efe032b83daaddd3e3" },
                { "et", "7d9347d11a3f935c510e8f070c8fd55261eacc7d2d911f3aa7ff925f27df037a4ad85aa8868fa4260f4cd17f1b87ec0b66963ec022ca5a6bd455c5c908a12fb9" },
                { "eu", "bb6ad6a1fcdbeb019561e75e807480071438ceb78727af83fd8ba05159d3f1f95ca98cad68550ab8301b63db7f763594de882b6885386593d8e3c8b79f51acbc" },
                { "fa", "3b697be4f50f423f2e00f92e22997ae5fdf443f1e08924e2b6d0133535d8f5d7a2dfb82942f2280e5192a4848cdceca580193e533239b6e1814b87288355e2e6" },
                { "ff", "74d5a3a25a04dd565cd1c2ee80bc61dc0a070355c72245ad15051be944a3cb5169ab934dffd7db4164dc2ac38dacc64c50474c0ec2e26d38cd01488e9d56da18" },
                { "fi", "36a76c494833f8c67612cb35c2cfaee0f30f8481685b42ce12f5873569e6f7afc2a417ddffa5e973423aa1a751b5e5f02664eaa50211a5cca87bca3855220017" },
                { "fr", "518005012d055a63a07d56f41779261446c46c57f473171994903b9257e96136c82727f3a43573db820a6de449fe9631775115ff5e5786bc7b33ec85d7c02d28" },
                { "fur", "a637483d63348c11967ce1895a31782e5c9d456987b75259f9b652a5ff06ce26b28a74a4cbe413722af2843d3dede132d024f360bc0a04c0aa739afbce69452d" },
                { "fy-NL", "ad88fb63447bff3ca7ded4fea09b9e4d465fbc26c685a0a7eb3b15419a5c47d1269a4838f730abd83d520388cb6c50fbfd2db2be39e44800c95c96cb922c3d50" },
                { "ga-IE", "4b276d52d46468b8fd69782f502591adcf563d3d6a15cc6115935b8e025c13b0bc6dd5182c61d1adcd8efbac1032621186069c2b174dcd1e5fd026d5ee5642a2" },
                { "gd", "858a0db9cbdb151e16177fd606510572b7a3ab27dcec8069fa133809ec489a0c199106c9016236464d57476f4afe5a38346852f51c278f2e75c682b22ff3b843" },
                { "gl", "4a7b4e55bb0e3c68ec6a2266bc99c732ed5ad089208de795e82d728c8b60582562ceecffa7ce476bc07e14102f9b0aeeb00cdf83709dc952701f35d3fa94ecc3" },
                { "gn", "46b1acd2a8e0c8f3332292299fcf402460de1d39f6ca448eef5694cf150273daf6c79e533557f65a4d13d597fc552ea212eb1267378f3a636177d5f7360cc112" },
                { "gu-IN", "c85ef4251c3303e3a17bcc449d50ba023055f275e8f5a7d7a1fe1e6942e32a711de1eac09c6870542f49ec5e4e34e3f49f04ccc18128e7ebf3e68e52b93ed9b9" },
                { "he", "12a6b1af675314002b1fea080be8555844be1b61fea6ec2d4ad93d08b80e9ef15a6089e7b1668746b3668f145fa95b4964db91d6fb0386cf626657d9352c4ca8" },
                { "hi-IN", "3f9b2d7040755557c2c92001fde48627c13da1ace957b7106d4e9027ed51c31884ef3f2cdf3898cf4321c76f19942834df830c86943f0f4d7584fedadca1bbe8" },
                { "hr", "addd25c87551740a73220b00070ebc692af9778a8c67bee753ec9ba6695e721e09bee6121fe86021dad8ba68105f4ea8f2c91ed4f486a4c9da2fd0b792abff00" },
                { "hsb", "deae32044d64947417789d717768dc020d0ff01bbef335fbe2978f190f9bc50ba76af7ea4606be56a63289b27539c0249ff4ce6b6e0c5b8e7cfc194fda948c5f" },
                { "hu", "03dc9b2f6ac638d72db534532842be7a9dca1c1512fdf2547360d2777e04f32e999c80b8cae5c901aaa6664ff9e77a8502138eb7cbff55e5cfacc4c4b22e2d74" },
                { "hy-AM", "9a508bfb355f8b6b80fd4a04d34bd87d2e96d4df76a4d3c547ebfa2cc2b1cbaa0a801f8444929dd3fc4486b24d6e95f404861f9afb9b4838c4ba0e5b7e487e48" },
                { "ia", "a2083fbb41afb98b17f1b2569b65e8951d0428166e9da39483ad8c0509c9335001ec5c9328a795c6af80b75aca61fd9515941f488784a50be10431eda703b716" },
                { "id", "9996c0998b75dd170bf134077faf08c2059c11a4a9fe69f89db2ae9dfdfcdcc25ff537af624158b98e6cd9ae744731738a8f485fcaeb062c8c2cd31cb6e4e87e" },
                { "is", "1cdb41ea8d5e6713d7a0cad010a6e0eee302d456748ab229a09791046a3bc3f8fe4c28d2d04324fa4563bef232a9351fbb502b4c8722d023e33306b86dc1878d" },
                { "it", "1652c8a2b3b8b1c31dd778e268818fad6e19b3492b6aebc112f35e479f32475905cefdb5d8073297cb5e32b3434816cb7fe2050a0b1a6919f75a1d1dfc62f6f2" },
                { "ja", "fe88e0671971c6d5c9b860d98e8f43a0c479880eea79b3ea4fb0da2dbb23f24f166ca117b32b69d6946c10910a919e2faa48971d1888822fd5103f5a0872610d" },
                { "ka", "85ec91b93ba46504d41d8f71e1f16b4ba834325eeee6f02fcbd6c12292ceac1e6d1be83cbd1d6b1886f7ac6f4dc90ea7acc0fb709dd18d818de2529d38c8d0a4" },
                { "kab", "f58146c5e9b019053136665ccb67d389fc564c1494d50f12308dea74bdf77633a3c2541807d7774d783ca74c5bf6bc691ff129ed70ab87e0aa8f0a35745f47f1" },
                { "kk", "eadaf728972ff8619a653b37c41d696b500666d54586368b38f2c5906b02d672417416301a8e3c0fa0cc3ad0b5815aa8627d7607f97cf92d239649bbee5dda6f" },
                { "km", "3900ceb11de9494eeb9a5b175512005de80e1b4143e72cb9c93dcb2b54e71e4c67480ddea26be4ed581d258947145b4614895ac61b8881d1e8a9170da0f073b1" },
                { "kn", "472d086f7b0aaefb782c87925227453c47d5f95558ddb68c9360d7110b7a002b2e76aba268e2baafcb3f1e5501b946a934a5fd1885c26d321a89589c28975d2d" },
                { "ko", "4af513d53d367b7ed33398f19b3c71a88dc4a0e2c4e72168c4de5de56fa670fd5032161982c34a8f83b6038b6a3ce6adb809eb5f31092f266a1cb69204b89760" },
                { "lij", "b17a67649cb57d28801b8765792df737a652896ddbe349adb71f8ce2a6f7ad9927e404bf16d6dc8fa3076f748d754075787f6c87b50ba3af6985be210abcf2a7" },
                { "lt", "a4d5adbaea79a8f585d7763f2c9e5d5105ad6aeaa80ce79cb8b560eb1e167724b97c980b898de3142cd2baeba6deaf53d92fe203f3b14239d23186b971da30dd" },
                { "lv", "13b3f3e8408bb57e8fc350624dc3966f249ba1941ce98f3b925ea60c01400e16b53824d052235fa688aa4cc2e58e058bf40b258f3770c8cffeb63da8b9c01ad5" },
                { "mk", "fd011d711c7f195918cb6688cdda3d45b48009c219c2df226a62415d4de715937e8b704f36590fdd2afe744e60656c76df2ea1004180e08211ef356fa5e6c92d" },
                { "mr", "1ec1f617453976e9d7e3440ccb5dcec480fb927421f3b21a349c061d46e24f8db5e4f843dae894de0e52aecdde84ddb650630d03a42b54dc620196754684a481" },
                { "ms", "233c6b5ef4bbd2128880a5a56fce326fa0e42a19544415ba3920c518bce0cab16537b4b355e528306fa20b1c0320811353778f247525a0b2705ea0660a347620" },
                { "my", "d32840371f3e3548da1adb3d9184184424d98eb7eb4bbe0f6b6bc5bd192f0fb6fe8698ea27e41ed25c90911c6ea1ff02546735d169ab118a304ea7ad3114ebfe" },
                { "nb-NO", "ede3550bb29063cc0de44542ccb6e0fbf60c36d405d2f90a6759c56730c5de23b99d85f0e2cf248ab36c0af82bb10c90f1e64986cf9683be4cc542b67f315144" },
                { "ne-NP", "c2b0c79af9fbcedd21aaa01410559363dfbabaf63b06f695df5d5fab9994f1c35b5f9415dab49910a57bec7f9147246608c76fd24f351cff6775145e70235e3d" },
                { "nl", "fa4b1df656dd9add615775c1adff48cafb288bab2ece406847f34d47ef6ea2fc7914887110c07071f0f97d78bfff5fec288330f7dd5c902750fcb5985180eca0" },
                { "nn-NO", "f62b1dc05b1d73074eab076a6177ffbef7d31176179c5a7e68389fa443addd72beb35135b2c331e1ed8102cf04d8aa39193b458265419a4d5221ef3fe9df1078" },
                { "oc", "a7ee60de9781282f02a6068003121801a42217bfef608253598d54f00ee3533d98e3f75be1d5b850b81bd7d3ad97ad5b70acf86ab2b7fb03e6294d3540348215" },
                { "pa-IN", "64a0e9962f6fc690bbe6a5ddf6588fffa0858e09a7ddda3c8aed243523e82df2a44cd3e804c61571fe75dad1ef1add84634ef728e80783b30feb3185c763656b" },
                { "pl", "1c424078dc906d3d1ef2021bab99b3b99d01b963a99fdc2f8b2e27742b76060b279a84abc33db541f9a048beb0f6972e5b6b66afae62b0207b2e83e78c22fab7" },
                { "pt-BR", "84a581d99aa3ecf7d0791d3959e9ab3387eef4846f0818ba9b5194e03bd44867cdcce5c300f1529a0da5836c94e2ab957a36c7608812b9f76d15d4dba80e919f" },
                { "pt-PT", "6fc4cf816632a56ca50d51447c796692bd0ed9310aa25ee998317291779651ee41aed85c3a001393222bb5678a69802d3d3d4f012671bccc28a0fa444faf989c" },
                { "rm", "bb492b89e2ea780a338172c6d581584af868b6e5da38a6e8b3b75cbc3ebdd60eeeba60c9558cdd1c7d2ed7cad2fdfb212d44ca5130b61e7c85c2b3d15ac19ffa" },
                { "ro", "cbebbbe94de871bd982cc5d9ae7f9a5de6bc4693ad8a00eb0370890f033f74661f5e93ef772f74c1981b68b309cf523604976f47ce40e123e6aca48506f0f167" },
                { "ru", "fa1b3d2b75e81cb4bb97045582b682a6874881787f9b4e6e6f44a6a514c6cea1a87c7d94138473b3a0b387a9370bf265aaacff16326b3882f5d901374443fe09" },
                { "sat", "f048cdb70254c9e77a9d06b5979fd64ada1b930a32246af25f419031b6cac497b4d6739da4b166e7f1c70247134de89542e878134f8d3ec2017d4acf86bfded8" },
                { "sc", "ff6fbd917a36de3f6432b5a2ec8a587ad6679e5c918618c4e9c7ee911ab73c2af6763f718b0df12ca0497a096863ea2aca67fa3ccd65e3c027268762c932c2d6" },
                { "sco", "8418953f72c0cc70f9067a6d73ab1b6dabd87a9e2f36362b7508db294510d12c1a6edfba02a79808d69e5d564c293b6d72fa59b4b68c84060a21475715da800a" },
                { "si", "4cc62e82078dcd9b0c2e0c1647e919a4add3b764566810c8dbb58c180274d3e5f6a14d4307ed2c3cb22d0c89a0748104be1884bb6fd217942fd641d4f465d799" },
                { "sk", "70e9a181d7ab858690210b2c98a6ad353b9ab58c91265a0a93d85308dcbe01fdd372edd9bf785e44e872b751d4f2675b38676198603dbd86332e2ea7b36c68b7" },
                { "skr", "bf325a2aae6fc5ef1490829f185974af27bd2b04d6b04c414b4b8e124719df870fd7a01c0a969b478358afcb6cbef52c3a3875571ac9c94339303b2d3d6a6c8b" },
                { "sl", "90f7fb0eed6c650116ae0d7e184b62f20529ed407f1b6ed2f390f765198c546f65b383813f7a264b0d692a4c789cd0cc240a16a5faf8daee8a88a56451fe3f33" },
                { "son", "0b86b568482f42e78c03b837d16dc8b40bbaec84cb9c5502dda07ae5e35066ecf5897eb25431dfbb26ebb909b29a2907137b99b7a52c881ac80a32aeadf23a78" },
                { "sq", "ba1e1d3a9c7658176fa77e83f1f4d5b158e5e420ba241f619a798fb67b227832f6fc947bb6e89749e33b5f1aefdc9eee9c64f288dcc33f017db913fedc0ed7ff" },
                { "sr", "724727cff63506c0bbb29515d0d33cfbfb5a1cd431c5beed9b2b3988fea69f99974e1f251c9b1d0ef05e19c0889b544867aec91ddd77d8852c20315c248e595d" },
                { "sv-SE", "26b264932ec643a9b80453fa63c88e2534cc8f8cf77226c7d65e82ead1a4a6d791dd41d115973c276345765d82b021ed6253d8c8af38867bb4215406cd2391ad" },
                { "szl", "bf0c9a205c77adf89ea267055cf6c608b3c125ddc96a15ffc433513a175d565f3e8163c17f350f4bbc730841a3b6a6b1c15e533327b72e59e959957b1f105aca" },
                { "ta", "c59e71431e19c42ebf3cf859f8413f5a280cd865a47b87375c3ec428688d9e3f3e76e59cb43445a793ccab437d2b02bb5c7a91481c3e0fc2b7dd04d9b14c9148" },
                { "te", "23b7910f528eff68dafab9c656927dcb313be48853b0e23f75d79be62193c506906030273c007139da1fbc393d4b7705c71d9e107fcb26c1c18455c61a0d96b2" },
                { "tg", "0a95082bebd80cd6973c47603562d370f28f467587b6b67d7f2015731498359342c9101fd3586b6e313f2c45abe03f49cd9c7fe9bb8db41e9b7b9b29a7b252f5" },
                { "th", "462f86d991c86cfae9ce86aa9d31102b67493d4a3d5aab683882498d22670e74ac01602c31b0f3faeb406c0992d36c11629da5f6c76db7187940a08591778ce4" },
                { "tl", "a27479f7fb6ecfcdc9989a32683f0be5f5c6ba62eec0fa9ceff69bb12fc390c65883d8398400ed325e0a4fa36169b6e7dc08820171e333531888a823af94128a" },
                { "tr", "39d397ecac936897f3bf17ba266bc978f337fcde22e0c7ce756236024f19a3b1f2f86baa320d11ba0693a37be1262feb82fe35ebd13998549b4d38e369c27a69" },
                { "trs", "b758059a086c9242190b564b1f58771c87993b3d3578420380cda5842e2aaaa3d8202ffda86763acf0f86e4fb3143682577f92904a4dd8bda8d6dd6a5fc5d853" },
                { "uk", "f892b02ca5b02e88428438fe727a3fc5491e59da542b2fadcd90447bb593ed7f6c4898bba7cb80031e4fd1cd9b5044184b6b9927ffe29eb44c8a12adb7cbd261" },
                { "ur", "26f545e75663359129b5a6c19324197540779661613bdacbb374d3a06db3d835f18886a580197eb9fcef4b5d65f63429cd02f066db9e5609aa7559d4f1590ecd" },
                { "uz", "24844cc5be02f2d12e192a51529fc0bbcf1a7b59433f1113ccb2a6dfa26989d408a82346a7343324c3d5df43ffef9cc827b5c5d578c88d3868dc4c56a3d60d2f" },
                { "vi", "088d193e1289c5b0416f806718a3a7d4ac7a2336cfceced93ed7a7a05fb8643cbbd4cfa943b84f60af7fc07357ecfa0efd9ca4bdca3cf9235737c54b5e38e48b" },
                { "xh", "5b26f98a3b9a5345927e272480385329dc210d2bdc38b0d77c64ac52bcda3f48d87695f89575cfed28397066c68c76fba37f134ea6eac87539e6611cdae2cbd2" },
                { "zh-CN", "1eecc0d8a9e5fe680fbab6fb4462b2244da985784b83f0f0a220a30ff2b60863e875dad646815884ec586ecbffd9aacfdaa6dcf8956512ca42829ac7c21c37ce" },
                { "zh-TW", "914efe589f1559e8fdc15972b0283c078fbef46e3ae78564d7006802900da8ba5d0e061199ef9578bf25449c2b27ca43734fddd1445eace5fc454e5d74664c71" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.1.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "9a5550fba32d3abc04ebaf47e8d46213929f19cf57f940f870d58d9ceb042459357be82650dd33fab7f68bdd152f2e03144565116fa5dd72ee795d8e93024800" },
                { "af", "3ac67c2105d8185e4dcf4e05e553b9bfc65e543268a467fc3a8f585213beb0eeac9c118fa58bc93d298807eff7089db855f408efcda28f77c7a779fd53d63813" },
                { "an", "54c307ef9cdcca44644e75977975f23c7abdd94ea70b335fe20437165541f101901feb6174b6478ab6aaf0d1ee35c58328b10a06d4e306a44fcecfa246b7b140" },
                { "ar", "0d090687baba78c812709928e11067d828a42de00f997ab95e4ffb23458d5cae73a54bbda8d18dc930c3c4ee0af5b850f2e082c7f50c59bbcab2dfc0a185eda5" },
                { "ast", "cb8c1632ab9291e23526a8c979c82a8e0bb2114ad33b6f7f4bddfbf40f262134e684e48ee199343718f68c060c06ff09adac62a49806773cd99aae3d739e92de" },
                { "az", "c7448da0a50717fb31d8da816101e1996bde278c34de9ab9e05460666890782731be3662bf2b211ae4d671df86c17c4897cd8d2e548af56fac25e26ad47056c5" },
                { "be", "00a21cbe9cbe5cb959677780a36f8301e35790bec2ca08c82875d04fae5a1c62e4e77695c01113c7371cb7e8e23acdee2ff0deae09c8b80019a128cac266d748" },
                { "bg", "7986241fa578641018bbea4acc3a9b679f4f18dc799a3d8caa39e38a9bfe222ce8cea4f91a137dd53d9dfa2456ce4b5a5b84ae85f7acd0f1ca6b94ac05e61f13" },
                { "bn", "df7a8d2f5f73824d245f30d95425a64595ea2bb82c87d2b1e7904d2d659a0b958cf524b383bd17499224788a004ffd0e356382d3a822957b27d5fb42f87636f7" },
                { "br", "c4a03c840a997a75b4088485b3ab322afce1b3ed45c02dbf398c4cae691f1df5565ab9a06c69cd44ba954630b90ddcdf2ae5597cd320f0ab48c8cd73659f50dc" },
                { "bs", "f6951addd2dddded6874c51b228507ebc1e154f2375d51228e9f96a1fc28b5439ac73484be08d63aa810d63d01a78455a34a1c206382402493aa2d132b0b1fe9" },
                { "ca", "53e57e62f1f56877959d50a9259aac1f69301c09192a0d6cd846a7a917397d04d175160a995523d4c7a0daea1c322d1d28399623c5a23107a64cd19e253d8cdb" },
                { "cak", "cc3741be9b000e48f35c8d811764a572797054602a5beeec9fcc9ea1cb0c6578950b37274a3e951123f26e85130e65521033ec11b6b545619e14c85f266f6455" },
                { "cs", "7b6f67ebc2a6b21559b1cb103f89aacdd948b472f301d5e2192052aa582386de4207e96af35c4df2596e4e41b539623dcc3fe77f0acbfebe5818bf4ee88a3084" },
                { "cy", "9ef352e2bf40e867807ae93fe840fc6ce627295be2bab4febd5357eee7d4a2f715e8c8ce76241e3ef48546a9fde73deb43f0d12824c87f91c95ac4098d9aeb0a" },
                { "da", "92ba0bb71aa9dc4690d19a1f7ee89a933fe6bfa9d58ec0b36552220e0cc60eba7f991358ce5db0c177ea05087c8d0a06b68dd77e524e299b5e0227442dce6188" },
                { "de", "e3583e66acd97337db66f127ba279ce31f15a1b3ad0bd557bdd71b755c496184409817d61fb844aeeaa73969afd2ebbe74b139bd432673ef2496bc21054f7fca" },
                { "dsb", "a7c01ca22f293a2e2ebf08e258a5815c874b8c087acd2beaccd776002e4d9e3a50937a8c294a1e109c46ed41190691a30c4d570eb966ba6fba4108af27165e58" },
                { "el", "d52c1040224a414d5122c424e9feaa3eb8159f95948d3538c677aff74f0ba41cd78c96c1ea1cfb07e174a145da5c0d398036705e55012ed92fa0764747582d34" },
                { "en-CA", "a53fbc1c5ee4e046d1d6b4276b65053e02e645656f4f9d043457bf7d131574d9a42d012d1b7e6002190c4828e619d7bd43d1ff4c464fd43b9faf1dd769b11663" },
                { "en-GB", "02ed6b0750989924d9513a822af5a4ac46d58da50914394de0843bebf6695b93b2f76746662713183c15e62c35544f9bef31cfab8e733264b5ccf13a0d0bf05a" },
                { "en-US", "3a3d7d5f6182852c425edb70f1f5d060b39953cd34a12774742997d32b7e9e5a7892e5fdeff70e599c76b2dc0d7f6d64b57234e7dfbf5b1f27a45b6bc7b906f2" },
                { "eo", "3cff85114846cf803b5fa8f603f0ab3f2c158a8e398d19b1638b5f448af2b8c764ca826a7f85c166318e8e98205a4483b7dd4247ffe59f38d8e9f2c224b07d5f" },
                { "es-AR", "c2c9bf8e2c7e03bbcbd7db5e2aecbb35552d38138b60f8c41905234af597a1cd923b1ab237db5678002a088939f268371132dee14dd11b70c9384989005c6dea" },
                { "es-CL", "e734ede6048ee3349c5aabd5e183bfbab79df1e6e785c9be5d471a13d7f3b9d4efa5f33b60871f575113d8d24fbedd6db3f169145465396bec11ac0e406b84f8" },
                { "es-ES", "229222decfffac47003e59c0c6918042c486bc95c6936f74882c41817e165a09568722f9217258867d2f0cf4b03ce8bc562574db748f039e50976398b853d5c9" },
                { "es-MX", "680be3695a96ad2f51548ecbf39a06c3e7f8d98d7245e7c9ff39121a0414ec9ecc4516fcc9c9c9bbdc8c2e60127a0f99ccdcb445bcbbd76127b3cf20da84a064" },
                { "et", "f106573d03005e3511c2c28b353eed548c19db81d7c8bb852a71e312074a0e96b7fc52b1df40cba9fa9ae6b649f6f2b8b8aa0c1b8542c0565eab0f677e0f7bd4" },
                { "eu", "e6dcd3533596448f1dffff84893219328163cde768df8653ddd16fab817adc074bd724079071cbfbc1b71e41afb2000c609ac42b85cb8e2538848d65f558ff4b" },
                { "fa", "d402599c72050bb06aba194b239e923d6e7d2f1f43b0ddb778e87f6c958d8126d8154d78ae574348b6fdf8f2c818362088030518ed35ad6bac383c3e08b0458a" },
                { "ff", "d92bf36cb65cd670a49f7140d803466a300ce94d9e83ae0bccc0fa698bbb96d61b2905ea8afaa62493222cbb4b543d1f9498bac65215da81601194b257eb59b5" },
                { "fi", "1ba4d9cc5d7da9c10a43023a18870be5610f5160b465ee4d425b41a69895d8300db40bfb6bfed7d40cfdc21da385a3b129513bd7856ce05b0e4d773d75eb6d3d" },
                { "fr", "5152b3e91daba7b37fb0274a23fad1542d59cb714b89552b61fc79ea927c91cbfcb5af9dc0556cdcb3ebe4101b5a24f1967440a3dcec97c9af926538b5f8fd98" },
                { "fur", "e8c00c1f3eb72eb647d412b278ec9ae1085001583274b85c35c4fd30df96215d5f442f30a5cfa907510eb28721c17395ba73220cee7204e88d77a2a267ce4f26" },
                { "fy-NL", "05eb3a7d2bc65fff82a140472f7c5c782c2935bbb9a815a2dbf79abc587c4f6952afc18cc43dc087be70f87085d095c71ac29b31f2f66d4c5d264a52f29968be" },
                { "ga-IE", "469205d8e7d6f00740d90208fae5abfc4119c0eca01207959837011c64f528ba227e60ed5e48386b135e568f009e994cc6cde118cc4ee478c525741acf25c1fc" },
                { "gd", "797758bf173141d5b30d78dca64b961157601de6c0f0b2d59c762089659092fe7e92eceeff5314521b84eb133a429ca554cccb7a3baa9effb3b1c9d42b27beca" },
                { "gl", "5c42483197af7661a588496a3e17c6a221e995f4db1acb878c5e0f225b95e4098303a345d4e604b8228f7842758052ca19377355561f73b0925793329e8cfe13" },
                { "gn", "0ca60ca4ad0ab1814abe612ea740149bf9162a608e79545786d1b75027369280d456ec013c1608590c0758ae5479e45c540c49006ff6e5eafa2a92d62efec6b4" },
                { "gu-IN", "5b204b9324ac1fb73d19df176535f47799d2ca3b8e584e06e6ed7e2b3b6258c01716842ed48e2a50bb55182c8d572a0a0bc9bf88cac6f240346c86c25c178b7c" },
                { "he", "ff3c85239ad403c5a89041f3f4265226ec2e3635bb10a20480abf748f9e5494204485c02656d9eca39f2744889f8be5be6c4d6c3f9380d8337f1487668fa6a13" },
                { "hi-IN", "0881a12364320bd2d1aac4dc0499efcb7bf04d6132d6f287ae85f5ddf664919b2c8e913365f98a18da002d53341a7591602ca6b9c779c45c730f4895a8185661" },
                { "hr", "d9565ae185dc00b17764f60cdcc4a9277dfeeac892602118f2b3cd17cf2c8b32dae1da708837b62130b9f392fdd2e6291e7ad35f4c80580448ad29b9da9e53de" },
                { "hsb", "2a01c17c94d58bcc357af2f7695ce2035a59fa308583186827de27f455fe2620301fa833d6c17882198d77e2e66f47e1c853c519b908177c509ba12fe82eb86f" },
                { "hu", "909b1d7e5662e02ef4b3553b065d7dc68f9caedce216ac1b623fd9e5348a4b539f76afc35c50acdf13e21d3b24882a464bf064067b03056675497e45f686133a" },
                { "hy-AM", "d5070cbb59a2b98dc2e173c4bcd12c4ab39b9840df30d5f190f16627428e8b1a7013908bb2f17cc3389b33680a871f43623119b8ffd58c556b7f4c94cb6f7ff6" },
                { "ia", "a1dd334d67a65951ed057cdee2b9f838687debe0b4ff6a9b59a7b0277d2f4faf8b0615296d1148f33787a1b1a4e1c8380f63ccd6cffe9683e04de6084c8a9d12" },
                { "id", "5d10d7993d3d283325a17ee2ce407b3930e81fc76179c7a9c6eb7f058f3dfc04d533c63936c59aacbe84571ce4f53ef82d8ba2d15a28a5e830d6cc366a4d29a1" },
                { "is", "e4b5990028fa11eef8459f88847a22714f0488288e8049d0d22d86a50a536cce59512a369bcbb6cdab8da177f3cfdf4723e425f3efc69a01dc38a8bd2605c4f2" },
                { "it", "90595d44ee664f2b2f4804a29125addc1825d011e01650738b0f1930b357f75f1b8d95456366a0e65a9de5f20ac3afd1a3d3df4d07b90f54dc67b6276b5451c1" },
                { "ja", "c1980e51db5548c032e6102a47c242988ebf0e495baaa39651fdf866de000bb0084feb4679842b3de86f805f2ec0fd74fbcc9d4a193ef4a8fee0ac0c4a94b22d" },
                { "ka", "029b085f1e8a7beab62c620e961f53f48bc2b2467d9aa97d4286fcd480a37a0dd701ab3c12734de96a5c11f1f22ce66f34993f54567dbe7c60c83c0a4edb2fff" },
                { "kab", "02efd394c034875d22eaa8ecf80307ffeb64a16f5886b6271e917dd1b4d01bcb47256693bb05e4252bcabc006bf66a08dae3399299ba0803fd7c66a71886a9f0" },
                { "kk", "da118c7b17608b0886f0f11b9af81a3bfb30540e146a38922c9a70cd2939bbd88964ef5746521436fee45f2fae3fa5c9894a5ac5294eafd8ab4be934ff57f09e" },
                { "km", "a0e1fcacfacee2e9d6919f5ce592aa9d0f96d4b841764e9750fbdd9551e3bf9b1ae448062166adcb6118643610f49b273c8b55db1450f6bca36a261e8dc37330" },
                { "kn", "8d735b4892a84abcb7e7e7546c30446ed113e9fae539724bcb06cbf77f6cd54a53bbe34bb25203deb626fc89d73353581bd529704b9878c88270fc206967cd75" },
                { "ko", "e751d999034a65b02b5663243ed2464de1de8e4bc21b5dcd533bdb03367d63bc9b76c613df059b3aba38cae4884bb5a32a125d3c40d028e267b2a9e54b237a06" },
                { "lij", "3e76ea4b4a9a9c7b34a8c53f4902056b105d8e8d1c12595eb21be08e97d635d32464a8b2ff808f2633ce22fb69dbdb268a85d55c7b59fcf2bc3a6d3b5aba40b1" },
                { "lt", "410fd6b0514452d18ccde2c19258170092bcdc839ac46f34961f6b7cc8845077282b81da18ce5d9749c09decf303859d2fec9e5b92ba5345787d5b15a142d810" },
                { "lv", "0523b067ce572229aa9f0c9cde8b423e6ad934aa683de9f9f1d34e9beddc2004fb1e36bb1431abc25e6037e2987c817f377d9f589fde88c5afe0cae14d680003" },
                { "mk", "8fefc09cdcc0adfc8c0807a49b387b594dcf41c754c4fb39a33000559e03dad1f1ced198e73d6b1f6cb496cf3dce1d0946a1cc472e7a0fdbcbd5438741d77f9b" },
                { "mr", "cf4a2f6d9d9b03cdefcad5448273790668a64ea0e9393d9b05c0146f3add1b9c0fb3b5ce655560b128b3256633a52a909b06e19807c47f2e8b93bbd6ae88f61f" },
                { "ms", "ea924c62e46b1222d3ca22a713c15c24a041de501936d386e249fff042ad682ceebbd21481f0d23ff058024e93b9450df84b63857e9b1c4fecacd2cc71df4b49" },
                { "my", "788d451ff3251448e7b595a6926b8ca2ea80368d82a7df623cbadf76b5919266bf2e74ba5683196d562e7a97cf3d388d99190e6b03912cd913ff08d6c08eee74" },
                { "nb-NO", "91fa5951a67f0a11af96a88eea7e455d6a9b5727e9642293a71fd6cdfa94a84c9009494174e0628542a8c261e1a68cc1588a6446d0acd685ddecbf8197390173" },
                { "ne-NP", "fbbd88ade0b64097a3b791791642747fe2635233ac31d5da3e67221c872e6d5aa7f3a3f02962c3234a4d644e4fe489a74303c2d61061417e6fe70a15d2b540c3" },
                { "nl", "f4d994f6387e5f8d0fd03366e89971df70829cd2c184f3c54406ddb3df9ff0f33b036f08e137a2e1f989269086858c755b494798a2b179d5d91500044075e6ee" },
                { "nn-NO", "6695d6597032b8dfc06e1dab56c9b7b5f4e9c4d8d67b8e96b60b3dd85c1c87507519caca815391d3ce17c8e3ee3e03a504df075baadc781e62c45c0af01009f1" },
                { "oc", "c55728bacf5aea259ad1cbc0eb496f20903e7dbd4ba8adb273f518631eb8ced6a2f613df23f8c4d45622f329360d469766d96c16eae8018e845c4aed76c51ec1" },
                { "pa-IN", "32f20ac94fb63971aa3cc9ee336840ea4cf53f27148aeb4f5842e62c3b501f9b9a41d9101d54fd1b2d9798f150dd8dd5b24e06f70ae0e84bad656a4e86ed8395" },
                { "pl", "1f5af1381e41c69651cc5d701d9e76a61257dd4600553736784178b5cd4e67e795c2829ca2f4e0fdd60302705e740e6ea90c5df272013f890f7b2a2b00b654aa" },
                { "pt-BR", "d83a70b2dc958e576a3f77c84c97a0d5e12d8f579d6659f03596c7e37f7bcbb161e1d668090ab55ab06cc1463147227c91950ea0181db35faeeec9ce3811c13f" },
                { "pt-PT", "c654552193c2da8f6d47aa2818e6ae263db3fc8c3a6483c8b11003b07677c4280407c300b230c9f17aabe8c65a19cd2d915fe4bfdc098b9d994fab60a59d1267" },
                { "rm", "977e5db7509313bb903422ccd0666f6ae1a1f6fa0f5818d94dd397ebff1dae9ef97b04e209260b1854d256e4468984483cebdcdab6e4fcb812d4821c4f329d37" },
                { "ro", "c29c77b5d56d271b57b7d1ff72c0ff0c39fc893fa55e06e20913eb751a2359019c5637508a00411a677665b44de9d4033fe36714aa8284acffe2b04a2ac6bb73" },
                { "ru", "d3daa513e196ed912a5766ce433d662e8166db1f330c3427123ee2a8e0d41e957078b27bfd0e955087c36875991704870c8aad111f3d402a4c2c32ea6f6f514a" },
                { "sat", "56f5f31314e7939f27ef76467ee882f232ffb0362484e40b569b628e61a40e359d581291cd64d4a05d1f7c0dc90146cb63c0a0332013d837a3df7cc321d7fd8c" },
                { "sc", "f1ed0c49f3e331fe4ea62ef0dd130e1f4b3e94dd58ead6b5d9ad94e74bc9c05ee863a73aa58e3f7c873aeb70701607ba3d104bc77ce73e991d2a02c560704d61" },
                { "sco", "671d09bf65bbd5acf4d9c1efd246486b6cf95a388f15caf3d2bf9035d9df44ea99b87567bf57a41e094d232e2ba2a260e1b6b5012fa92fb05c2b4ce04b5844ef" },
                { "si", "096902e4614389954287d129c80fc1037faf07c53bf9260eaf43474b9d49a1e58b28ebe374d2284d81b2cfc95e8a7bbff67a01531a4dfa691860ea5c231a07c7" },
                { "sk", "a499a9a898efab5fcd17ff55f7da88dcebd3d5bfc3c31c1a4f915ea80430ebb95dffec087b9a3f3e98d2e17907bab3efaa0513228d1a785b43a89f91e4087a7f" },
                { "skr", "eb7452f85e9b69584f98110b822c19ef5e99c6c1fb8ba748ed2af40fd59b612208bbcb1e547968fc78e25ab27aa00b7c311f679bc2eea338bf4f4416621fcf34" },
                { "sl", "e81c6617e8754e03665fffcb3f338bcb96b7105d087b720367204f27e03a34a6ef52788a9a865686f443e5bb37530e0f9afb40b34350a18e97e4b146122d0d4a" },
                { "son", "89cb63eff2ede9471ca1d02c8b8e732863ec0a5aaffdcb5d0e7972c379e86b9c254f6272ef9b94b2cb32cc6b81cc313e3a9c9a5f40c0b4fbbff4409812f9c0b6" },
                { "sq", "f471f83a47e43d2b99667233e54a01472eb2ebf62c1666cd941697e571e1a2a4910a2622f87c3a01c0c1ca4f0dc236d80bfc5acc01ce7a7ffb80b5bd8cebd6bc" },
                { "sr", "01dc5e40864fc1aa9801008442422fe77c221715f2a8944401003930fe70ec44f6920aee97e16f086462a5e91f2da817a61755770c340219085b11cad07ccc15" },
                { "sv-SE", "ae3aaf80beae95def09250664edaa3fc4c397dcb5c72f3c3aa9709e4926f30cc550a661da3b317cfb3aa32587bc849fddaeb845af9ddd75486a8fc4393016583" },
                { "szl", "52e3c6397e615fa511574921a7aaef2b5820b1103584e5d88c6da379f218c647fb3876a847c4414aa9c72971866a906a1c6d64c8fe4ef85d5828d4df98bfb7b9" },
                { "ta", "0fb5b2eb042a6c9db3c9bc41cf9e14b3dd87d9d57c5172dc1bf2cdd3c11bebe23396a1f74cece9dc6883e0e371e3cdd20be41cf27e7391f4c4c5a610b5148d17" },
                { "te", "bffa0ec547dc1cfab70550816e77529f263e8a5e36d6d3420c14fe27b48af95105f6d65f02fc0d17d727b414280682545922828a1e9843de00983ec6cf9dce57" },
                { "tg", "26e962573d28fa73c6782f6921282950c02318ad66be9f900c24c1a07ddb11e44984f85c31e22beb4e9114e980579c251d7da1026513d05725c1733408215395" },
                { "th", "103227954ba27c546a0da015c1d4d4163262803c673b5f535ca21fe89ad7d2d24b58f638ae5d904f2391145493b19f148eb6f840cdcb294282efacb84c0100b4" },
                { "tl", "33de586a086d2d90e538b8d75ff1c52897730fff53d4143d0513883613a9da5aadbad912cf80d850e4396dedcd63ab4c3ddd55c10ee58bafe9e60cb354e1d562" },
                { "tr", "201dfac0a51c95512ad924d1059044028522b6ec2fa6c74ed5b5d6ba43f8ae93a81123af161b41d7ea28b5d58f0fadd99b7bc79573f3bbd0d5f1c3005afad11d" },
                { "trs", "048e4692c61c94f81978da2d0c13e120ed3b53628e2467a893653db124112ce2f24d0ed4ff33be43fab9d56ddb20b567ac1c97b0f239feda0042b73b8848f1d2" },
                { "uk", "7525ac38673eeb9b4aaf340026d7bb7bd28712b61faa4ee9108cb917cf4aff4baafa1c4d2104ca8ba094f2a7996517ffceb7788a6ce70fac51220b3da432f767" },
                { "ur", "763ff4970d64c7da979bb6126fceaa5e66856b24a7376d5df9c3759ba75feff5c4a90b0efde89cf8d3a96e739a295125079dd5cb428eca8a02b43208e7b45561" },
                { "uz", "a999add9d1aeced7fcdffd8a5aaff209ff458dbef970f249e3166353a155a1d43f0c66356609525f88c588e517ddb6af29f9b6028d744744ced0e396aa7f85d1" },
                { "vi", "1c67958608a60b14ece2d6557881066a4cb781684b5ec51db7e097a9534c302797ccbe998385b00005598b19d011ec4ad9c5ee57d86a0ef72d6ae63621fc3499" },
                { "xh", "1e46fea6dfc4869c2e41eff630ef706dd3edbd2535970a250580bde2c103c2dd0b47ec325ce5d8e55e5f4b5895f3e8c01a5bd107b139f7ac216bc8c7fb8a5a74" },
                { "zh-CN", "d45ff7c77051c691a3285ca9bc024b966f45cc7af809aa01396b29932398265cd61f24408d539bed372e4fcf325eb3de65f2863a0345a18ee135f10e6fef0df1" },
                { "zh-TW", "5bb6339dccad29994c1258d8e7577ba6a385352d35c03822d8b6b6e7a841c916863393d489a4646bdbae3f7c314ad78562d23ef451473f0f5c6b6065250932cd" }
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
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
                Triple current = new(matchVersion.Value);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }
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
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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
            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
