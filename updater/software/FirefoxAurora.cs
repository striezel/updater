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
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "119.0b2";

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
            // https://ftp.mozilla.org/pub/devedition/releases/119.0b2/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "0c9d6d78530ef9b0941f01670a952013edf554043001f2cebac0711c9eab16fb927f389179cb7231792e850956cf1ff8cd2d4d9e0f964aa5050ef3d55b07a2c4" },
                { "af", "879452416a04244258e444b2ebc3d89c9a7fb74f94061ecfbe3323ba373857960ead596f7db3e4672b398726b4e2a19a4a0e8bf0f476c76ca43db600f8e2e650" },
                { "an", "eba5144f7ae73ff440cf26543e86a49566712ca67b566bf7435fdee10aef5c2b5ac91a601dee3a8f280e256b2e5e30490723f335f277059f73ed776aa4cad924" },
                { "ar", "2c34103147daaad3406ce9bad043be76d64195cbe236d575c3a50130ce828ec2f03fa4e71e2928c3018da715a2fd7ac3abe302f0f3d3eff6e54623f78683e029" },
                { "ast", "0fa52daef4a79e70d32b2811a0c044f83beef3e3aa99e797d7f74124ebe3ca0def2ba31311bc653723d0639a1112d2329d0eaf5c3d4e99c79aef0d0cd786991c" },
                { "az", "7f47b16a78cff8bea4b5fc29ad5d3dffc666e3cf3d5d841b8b18d9810442368b9000c38f02303efdb3873da05136e8ea2475b2ea0ff0f0b932c2357f363c1e59" },
                { "be", "5c1464d8d4d8cd466bdc29ae26898c2a98aa4b499baab5c098a1f614ebef041bb53047215a30bf80f5a27de0d6ba2e63f7fa8e99e30b85f14e6105e5cdb4772d" },
                { "bg", "6ef13cc1f6695977c5e626f82557e4f541b4a19e2245e4791941d1540d5277745db3b7a13ba9ef2c1dc84fc2f213b7baa66742c8838acca8dc21598801d0b8f9" },
                { "bn", "4b813099312d09f3634f53b9c3f6c24af81c6093633f23343379c5c436a8e38cc7039bc7b0447d7b2e31043157ffbb5f18ded981d33040e76d3f77b8afdc54d6" },
                { "br", "be370cd1fe466c7a6099e92d9d44560f5b616ce98697cdf067c0020e4cad2dd6e46c15e30a0ac3c38a25ebed01e89def65072c2e9cf68ca5f16038e28d97671b" },
                { "bs", "ac552d36cb6f6cfeb08d8137323d18a679092b220b581222d9850bcd9aab400ce297a153f3b5ce4525e4c6af35f31c149d1a298aa37e3d839937f14a419ea9d1" },
                { "ca", "00b1b16b04864d31b84066245724c11fcaada1a686326d62ad8b0fdfc7703ce85c1b0ebf3586296dceb039ee933243047f843665ab526ede0871b24ef4059a51" },
                { "cak", "c374ff9ac3292969704fe4e8de02dcf2a6a236ef5689ef9520710633433915fa3f29974165221720b21cb2f6aceb76eef3c331a97edcec069bf845125837655c" },
                { "cs", "c05b9a896a4e017d26a304c4b5d6514069c1c91c41d343354e1d2fd6f00e289b0c046c43d5aa842ddfb79bff76db4ca1332ad1dfc6d22edf597942c4770e371f" },
                { "cy", "16748c80a887b4b9a48b21fcd81c4227149a8b7650ba7c397592e5ada46c7208b49570e40f6df76cda2161617e3b9d0719f254f7dbb1745d5ccb299f1bce3058" },
                { "da", "226933d6eaf534aa29637c48d8a78000ef773cdaef5cd4063d658f18243a65795f1476879040465dd6a413894c6a119f0fa908ada589b9a8b41a16a5b1d9cf4e" },
                { "de", "709eed8c7c065f0e88fe6c139aa5deff5484707c230edbb61ffaa9586c60f8d1e273f8e67155203ab3da7ae1e8d8bcd9fca1efa361b82f93502fe8c07dc96ce6" },
                { "dsb", "b071534c5a365ea6f568190051bc7bae5da7696e439929b978585b0594fa5b7e17f36deb53d41f79c0f45b06999db4aa80f4abcf81ca8dc810f9e6f46bb3c678" },
                { "el", "89488fd58962f65a0643b59343ec0b7ca44c7f4088b89b0d6172d310cf193536e90302029cc493fd55796f7cbe9c392da6080e23fdbc03f6b82e68c146d063b5" },
                { "en-CA", "41ec7291ad437bd5f524658bbd816ebb6fb5a28b8b1814623654bbec3119f81a4d1240298778f3a94b9f10086434fba6274efa456451650ff876e222847e65f8" },
                { "en-GB", "253256737e500d0c77597bd6efd17c69cfd35319d9b6b3063c8af7132aefeb26b7a4ad1a83036c20d896c457d9a8ac391c0ae898939bcca6e86f1760cb6e4909" },
                { "en-US", "05da38cc09ff245222fbdde43651e66a5bf8fda643fdf1ae4768ad2e97704c204618818705b9ed057f17cea3e8348702e485f31e3c1cf2b1d1018f2bf260b360" },
                { "eo", "30372c159319501dce41308c9f9237d20229e5c82394ea56bcb11f307bf2d4258b0224975e11a953cc414b22b1d86999c89a6aed2bbe41ddcc02f3bd2be4dd11" },
                { "es-AR", "c2823eadaa998b86621a18eb1d2843225e131f11a946cc061175bfc8e6adac7524032a8beb74fd57c3b2987a8e0ea343b4d32d6f367e38627bd5b85faaa9ba73" },
                { "es-CL", "68fe74453970a756282cef036cf90274e744b0c9f155b70606179a0ae1031e850de4a714d0824e57d4b5b13c627faf3a71df4168f8fcce2148c82edadd8c9216" },
                { "es-ES", "4bff9783fdb90f921709ca51b4c237fbf013a09198c534ee8ebbacc0f236dd39c03199bfdd393293fe0ab62f1526d657db48f45dc9744ee18e3a2ab34ca3b97d" },
                { "es-MX", "83e10033582d41164fa9259304a8404eba5914b4aa5947d873625343b8c1c8146d340755dea78d5a676dcfb313dc19d39488119fbaa6d5208b3d48c0a13a9b1e" },
                { "et", "45667d77fb3134cc15e97f2353f7d831f8eb953b55cceba874c072dcd24c478438a3248942957117592d5677aa4e7a0820deb752f8b74874ec630a8a5b30a550" },
                { "eu", "ccda0ea65acb44be0064085e332700b30526e58a82bb40f3175d7b2f52f1585f36acb6ea6006ef52a2426e5c0fe7b9571b6a50b53bf9213ddbe3fd28cbd70988" },
                { "fa", "e898227eb663b3551659596ee59008e4f91b0b0b3efa5f747c9c486ba874f248c082c91eac7d2bd8c6d3560e2093abb851f5cac85c5605c331be3b7745064b5d" },
                { "ff", "f8d0b927c7a2a32d0fa89e94143957aa3b486f990b0844801e05cdebc02ca0caa2394a2f1f21b2413a11e622bcd4a1a1f416b19e797b7ce86592f221236ebf34" },
                { "fi", "d888778c04736eb5f021171f62259ff2d57b2206e1f41603cdc50f90b712c19b588a2d13dbda61b5a2a900682403e77972ec7f458680a9c713500ad284555c3f" },
                { "fr", "5957eb2427d0b96a7627d2a6fb741630b90e07af2719ae5a495349d5696dd0f254857eccc2e730cf6486a4e9c497f933867bf7716836c61dd57671ccb22a15f8" },
                { "fur", "4d2983b861081ae148536f0c260701262d3970cae73ebe15e8b7336a59557f283bdffeda59cf2402954da844319a839c7da08ec7a713fca0f846f7f56f369472" },
                { "fy-NL", "e6e44cbcbe55c2ab3cb44f0177b1428ed2a6cbf117ad3108ac364345f53d5c8f0280014500bd0b8c2c12a9c7bd48e5c6d8ab32229d53292ecbe52f1c11d4c818" },
                { "ga-IE", "7415f87cab9ac7c3aa5d5689637d031c4a544f97809306b9c5763b4f5491c65cb8c60aad2b66302f49841410c6e376d43c3a6b1ea87bd2068cdce0c8063856bb" },
                { "gd", "febbb98f30c6a9f47e86d547ecc3a2b98f0910ebcc33d8d85c6626e0708d6f6055242d91942b02bd950f9959cfa0d666ca2331e06f342b6dafcd5d197b1f1125" },
                { "gl", "5056506f78f4d02a33d1775b0fd6e7db6405c05fd017f119313e82d2b4bbded82d503a2b52d2e87e9f680f0a4f350b6af07624d97290a72e95cf1bdbc0c87860" },
                { "gn", "7340077a7f890d0715b37e990d8a23922297d8ffc9e2c2d52c8ca0ef8750f1fa268447451045c254b379ad9f7f48700c2708af58057743387b3239afcfd723ca" },
                { "gu-IN", "dcc131d7edb7edf36b83cc908e2ea05592dc86d7be2a203cc97ecf9ec41071dba06838db7899474eb0e93b9186a49cf8fa94a596f4711eb72118f41d28acc013" },
                { "he", "b178776bf531cbd535db7027419893dce2c183c909bc0363292d739bb119d4a987d031f38539effa7e6c588a7520a1db4acaf1aa575d288f5c3c080bd912022f" },
                { "hi-IN", "0b28a68c841aab9795a25f0105f5d0de3b833e66a5575efe1ee531a3b285c53a9371d7dcc997609fdba57348615841b3eb5c42222fa28005c334679b67f96ccd" },
                { "hr", "05befbba500464c226cd888649f6ebb40f9ffddc65542c1858b64d8873f8cf57555cb1e34fd1b686277daa5fd1ec0b695dc5e1138cc56ae953281f1d2bd354d3" },
                { "hsb", "c70d58fa39b488c994d32134383c4d41c9535cda119f8752d9a1e9412db52df3ca8ddfe867d45008dbea87f96a3bc248c8d46b75b23d52de9eb6e34e7dd53213" },
                { "hu", "fd0e643b0ab1aaac81516911146fd957e07d1c020439ad0e6aa6cb0173ed4ebb08fab7dd2c69b66145b1e7a39a1215a2e26af973c783b458a472690c85ce6db3" },
                { "hy-AM", "d65dd42aa378f0ebf8a55c304c9ab73a4c721db784aecd2cc7266822909b171deb040cd2b6ec69b61d2e128c84064869e8207ceb64d51fa42ffc7d4e40bd8a90" },
                { "ia", "ddb2ad4635a83740dd286c436d0e0244a14b7a1cb1a7a52347036e7ab62ea673869f2be778f9f2e1ad7fff832e55828a96315e6d763f486b0ab6d65f4f6575d3" },
                { "id", "9fab881f08b6d55f7b2d2ca4342aae9961559a6e05ba28b447b405f7977ffe668ffa6c38253c64d3e9ef090e45c974798bd35db84cb219b07b329c1ea4aeb271" },
                { "is", "6ddb39efbd1e7fe08d55510022bb826c210c9e373034a38d796bd446ac4772fcb585413fc2bff922730b9d3783ddd2254d4a8fd0cca18dc409722a694a0f49e9" },
                { "it", "6b777d783e9b6fc84d21982f50f5365325655b5bc1dee925e843764c9488598a738fd445a01ed9f71361e8cc15b6722191668008797bac35de5e9f2099e07fe3" },
                { "ja", "b8ca824885377d3b15fbb566ba8798e5af8cc39b261e933a5e41578893dff08795bbaad45dd7db5019d2b33df20b5fd5ff3d98074d90902b6c9f177dbd1187c5" },
                { "ka", "fdb3393415812f7ed598c20b93dca50727029e2b1422ab9986f426aee999c6fc99256e8de2b4a18e0246ebd4b8ba71973078cae7724de7277efccccd907179c8" },
                { "kab", "2463f744be3c0c3367cc07f4bacb7a86dec1bcab92845a8bb4bee46aae08a78a5603a833d50d257a6fc597174d567f2af6f223e2c16cd2a17445ca034360980a" },
                { "kk", "d89d155a1c8a547537780777919f81828978831489b3a2b655ee82d8ccc341bc17a04dcf737e0796e3ca9ff19e99d57d9425aea540fac4b1d93bf5a0644afd04" },
                { "km", "99df7c42b2999cb8ba42c213175b630ab25101a60cc2c4616192c3a54c1912e21d2669b86ade041a7c771aac80515ef37b415556030d410379c238228e3c9f3a" },
                { "kn", "886ac25562e11c34a50056b6c4501d136054256cf02abda1b040fab72feaa505aee0aa9f2ba0085914f41c2f965281ae4169ecde7597b67a741fb86195c0b31c" },
                { "ko", "cac96adece70d038e8bc0a04d8c05925b511f0f5a7effbc725ae6ce33c905598b19e3af7a1573c573eeb7254c3b53cfc2c2da4ca04d77d24a9b60d3a507b8b40" },
                { "lij", "0383a885cced4088998d8abd2863f6537ae4d4c8190056a7698d4a545c8585da0e2762f40a96b9fdc9f45b47cce387b49752a65bd1e749110dcac5fdb1a77a5d" },
                { "lt", "d66fa4371a60acbad35d00d5ded1147a7da9289e54a562f4236da7e06554671a5a49e2874042bb7ffa4020871f01596559cec3c6386121e88e523b5cec1ecae1" },
                { "lv", "d90a7cd82d659aa5a46b80864477a6d7d6d530eddd471f5bb2a8be15c517f98c38f587c4a3cc59d72b504dd373de73c301dc356292cd67a1713b8b4c04c67415" },
                { "mk", "cf54f79379c9854c08dbd3d45884aa30b82c37bad32072b40592026f1d3eb8b046d30608a3bbe58babc41f3d9ad2a86a854a8aabc05aa44f97c0eeeec8d2fc9b" },
                { "mr", "389cc03901882a11e22e49a4ea1bc0a13eef2c38ebc0ac8e68c83eb8224dc93d1027b92cb4c6d79107edcf26131230c8322a340f94ca7ec4bcd7a96524f3e2a2" },
                { "ms", "0baf2d7b2d9ff1328d75a471147a13e3065ffdf274a1a0ae150886031d462bf38048c20337b5087a835306eecabec6cdbd1a2a6be3b97192aa8e29c2862ea72f" },
                { "my", "c8365afdb31fc5be1390e7928dc2126de7667929440ae235e99d2c4403908b220b0ec5ba5f06045a9b054a1e1fac82d0f4604df554d180a6e5c6d947c635ae28" },
                { "nb-NO", "e7cd4fe5959c11baaab51b7662cb17e79a55a3238058f17f1077120b625f1b0918d427e73648659f1dfa1dc540835d498f2b8701c1529f9acc7301434d6e2e10" },
                { "ne-NP", "01dcd7db24b1b484d8a3eb2728864cfff11b6f1145ba96ae3b26aaf86296a59e8500181afab49edf90b8c8f2140677e708a955975fff930cf47e9f290014838c" },
                { "nl", "8f20e1e7d0835dc5d3fb1dd61c259c771f92b64a76447044131dd03f20530a88d02d0a8c0184aff14ccf16931e58713e208531a1ad9a2d8849efbf010e2150c9" },
                { "nn-NO", "3cf9f78e246d0677b16785d512146352c6925b5d1e6b84225bc7756be73377b50179518da293ced6cc8e0a4711c35be0b40a3f9c30a5e6e2a9980b0b0291d71f" },
                { "oc", "8210c7093936e96f227f483d4ac85d5d21eb18c8d0ba103ec7722012cfc29db1afe9c49570602f3020c50edb7617f70054f7814dfbe96f4bd5a9d85ff499832a" },
                { "pa-IN", "abe04ebfbe3792a5f414e36ea877ed98c50e11bcae0f0f995ae60def59854fbd1431bc63ddb6e3dea7fb230c03de36c2e4bcd9f8d1d4923fec63f95e4c262b82" },
                { "pl", "982b1852197e448dcee90128b735aa3d1f8e83fbc8185c326bc6b934a32a56752b9bf331565c0d31ab7fda5337004bed0f12edab5256cd4e5dd331e7f3e124e6" },
                { "pt-BR", "6cf5642a07454a96eeb4d4ac2111e5bfe77047012fe4083d8b0fd2b7d6d63c935e95f77e8d2a154ba3fad6230ebd27f05543ea11bd233e4fca72356bbd3c6e5e" },
                { "pt-PT", "83e0a659bff1a9f7389b461f3081551ef8424462c8de853f20036e58bf9a9941e06615e491d80b8ab3f7c5f69368288dba70ea2885e90183e2ab93ddc172d5de" },
                { "rm", "43d0ae6d6bfad4a4727c51d117fe879e43aa6fee17823cf2fc9c9cd0b9a56a6bcc9abb451d0fc16881a9a448d10905e73f9ec7a9e97fc270e2b9c41575de91c0" },
                { "ro", "79c8d3cbeb11d68831f71d2ccaa13cf056c2c2aab9c4e6ce8da8565f19a8eb5e8725e43ada87157a3c148aaf6ea491c7690c1a499c5d77cc97dacc391af63c5f" },
                { "ru", "ee3f712a1735341daa32890a2eddff8a1e7e3c976c04babb6e90bd58f4acef84be832c63e7a48320e1aae9bd7643ebbd238a4ec080aa8e3814ec6dc4b912c539" },
                { "sat", "79fdae91d2120e4ea6e7d42a4d0d00ce8b13a97124540b4f86243ae4679b7ec1ab9c8c865b4090cff6b558daa946bdbd48b4c3c07742a71f35c126ff070df211" },
                { "sc", "4e374da8608896a8a087049c9b7152a4d4ee3a4f688f2bbe80131441decd7d03f59c73d28ac5c88741da1f33f1a6f6ade5851b11a55cf68a97555d6941b1f57c" },
                { "sco", "ca250e66fb78a089926ce231c3c64d39c341addd24ac74dc9ee8d8aa6861c212e6dba112d15dc050d3d393ce6ec069766cadcef5c1eb7b365121600d40f22aa0" },
                { "si", "daeebf882cc743ab34476207ab184a2a0bbf82611fb4783b37f8f96e1c5b2f0dc2982abc04863afe83b8f1bfb2aa5a245e71d6233123557b9530b14e5ae839b3" },
                { "sk", "45bd7f9d02d0f884436cb0218b97e30751a63433265d70dc532eaefb1d4ac90bb5b5da3c7c17e47e25d9e06576f25b59f65178329430b70fbde633c02203e426" },
                { "sl", "bcb06ec89c240c22f4858fcfbcdc47804bc85420955db3e4e50507b38135da871fa296df615e44a61be91a8018d5dae01bbd0b33d62589c2c03db5c354406d37" },
                { "son", "98da8b3b3394129d7b67870c07c6bfaa57fe76de0e7aeb1b8efd5b5216174817d63765dfbd8e84638c3063c15b58f10559ff3373869cb87a3922caeab9d6409e" },
                { "sq", "82b7d325a47a21fead1bf4af44a386fde1357675eb99a5773433a55c337b46ecea47d28c017d274baa3729055a817dd5e1008a4db12285f9da3f27a5cfa096bc" },
                { "sr", "1f45148d2720dcbe59a7c71104f8dc9d22b312c88c7b846946ec269d3e0aafdf3a8aa7d4cfa63649d4f0f3b9eb40c8c7a38388f2cf5ef896403b56ab706d40c0" },
                { "sv-SE", "963cec86689c7613d02870988c3bbffb60c8487d17302427e67c2f78ffb0516ec9c8e82cb0339e625ba76e5fb13596aa0e25daf200d4196df57868501b0ef1f3" },
                { "szl", "64de95ecc4d79dbd75d7eec7a23ae62f9e80dba9b8e4a7a404ad467258110c8e5c411cee76815dcb9683f26053bd22870c0af37ca03418f07cafa03f77ea2a22" },
                { "ta", "484b25a6de4c60041d0a80a0a72bb3a455c0d1834efa68ea19ea5a6c56b13493aec96fafccac1f58af80db26603159ec8189c3f4f3feb647b73bbb8d353f9b4c" },
                { "te", "020b103fe768d9478f5c4e4a8a65dfc3b10e6ad78c644a632e9ff2093f77d825e6e96b5527145d5d724815e2026f1fbc7cdfc1e8f78533150d471b46055887ee" },
                { "tg", "ce076f2d408a8c6c38a8d9c4524f12930717df7dca042f60baff00fdfa8603ad15ec47f908d7c68fefe27f0d40a76f4b8b03fccefe83ccc775f784acee9f7354" },
                { "th", "713a88f80809f05613daa2ad02762dafa8ed660cf7b746a1ef24c10ba4e31a711b560d0953453cc75b7c890a637367b6aced86c68c3389d05464b2864e5c749c" },
                { "tl", "c9a88da207c081f4775b2face7a8f5f55348b6418d8b0bc479df6e2a37c89fca74d8a598ee5d79046b2246f86fc15a508c5422d6ba89fc4fe0018ee3979423f1" },
                { "tr", "daac1a1d6218b3cc1d4224aea9a8be345cc232df19ad8914839762ebb345b7fbe9fb157e5a127f4a2396f71fb5f86802cbdb99a0521252a55c33ae884b9ccf86" },
                { "trs", "b5e4ced17b89cdba0862f1ea99b86744deb9158fbbfacb1eeaa010404b89de75add8fe59b6fbc0df180b3fe1774b5d51dbf5e78910c8daa9a3fdf876a4de4556" },
                { "uk", "5fe61590e2486c64502bb7f036202c1d148194dde0900655ed4b596e9632fb382eedb61d62361e855c6dfc6c48a73ea0d3adf621981bd8a75e9f80114277b2a3" },
                { "ur", "367709adf59cb633b14196629bfe1015548a257a5ec5604309e2eb3137df631d2c85758b921125f05a04a2d60194de6792f036f7234907bca0a08e104717e9e4" },
                { "uz", "4c2eeeb338339fbe0f14ad5bec4358a74bb75b9b6f21a9865dd2a899ebd19abadd96126d0d075bd2534c8118a03697ac4a8024f9872383dfcea42e3174c83bb9" },
                { "vi", "5ae2e95fea432de9a228a31603f6f46e2571b50377f8b6c7adc47729524c4c17debf3dd89e719b1a0d11e50b72046ac362a732c9abffaacbb4434352f701246b" },
                { "xh", "ed83bee0e759f38c18a0edf9e27c2319149141cb47a6f40753836ed4387f5271b6220a7a9f4b46be9e8e63ef2d4a07486b4621d36c7e2774e7e60fc6a777ba1f" },
                { "zh-CN", "73510d443c5d01cd4054c5652719bba3b84a4fdba1f0916d76a961db29b0d36ebd7715bdf25a44a7c178926b292d51785ad544307ed892467e13cf0c842466a8" },
                { "zh-TW", "da94b632032c70abc31f70f94a591722ca8de00969192e15a2ddc3d5fd093449a98c574cca50d74c4b9fb42003004d28f2df4f694f7aaa2f0d42b05f20f9cd50" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/119.0b2/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "4a2f7cdd21578e6e1f8aa58997d59c0b0f9ea86b77cd7b329aac8d1eea681748214d727e7e1a486b5776f91025b8d3dda042f991c81b1d33f804f8fb2d4704c3" },
                { "af", "2ba16bfb4a7867182f9b58c454113cafe90a4b512ada93094b1c4c88c8b2c661966f9fa95fe73771f95269152b186736aecb642c3ce3d77fa005acba68fe5048" },
                { "an", "e638715576a9ab025d465c9635469b3c7e1982bfd76392a8204359171b1ac7de6af5227bfa11d859cac61e087739e81c090ddcd56e0adaf3b9b4dc5f69674887" },
                { "ar", "ffacbcabc2c8161cf4a5af5f1bad19ad4c105e55d1622b7c4d79b9d2279c4b5f7c8bc4b23b86ac076bb7a0bb4369801fdb5709528ed28eda8480c81b2e497993" },
                { "ast", "35c308fe580dc92cdee66089b35b80ac903619f34d3e1ce353fa07ffcb35e6e770b9dc708c379d2e44f1da3e82203a622b0d3380d2fca13e0c760ad8360c0e6c" },
                { "az", "0ce6442cab4ce1d1060dbf15d6c7389f51411c2cf4519c981ac3b6106a49d0eb04e6321e392200c23618b56b0a4d767ed646566ae9818dc4f013045ac768f872" },
                { "be", "6bca5f8d7e8fde0764ab7bda85a0d9406d738da09591e2101786ca938002e52a9b1c62575b12393f3f716dbe81b5de16245573124bc21c6ecd3085eee4a49858" },
                { "bg", "c1308a34539e0c4abecdfd0285fdc204cbb554b299747884827760c663a2e08f579c9e7125c7e7c7f7def7683249f38038f6ff10b03f6d0c199b01266f49f6f3" },
                { "bn", "37a7a8fb182b709420f5beb9b33c05cd51aa615e4e61ef0b14dd3215ed18cdadcf00438b95f24be53efc146d2050d8941c42c9afd54f73057362f94a885be93a" },
                { "br", "8ca4fa9047d1d6cff399a25a27f69801c23f30d47f105aaad14598425dc5bd0d6c75b9fbb1ed08ae2d63f0a2c314c3b0658d6a508a11ae64aeb9aa5ee2144932" },
                { "bs", "0e14d409ecec86208b62ee06880c5e617ded957c8cb872c164f1a9535f0a7b8d28e9fc7db2154d2f2748e0fa3f0ed7195b9a74baf2d37b4f33a341d7b75e68a6" },
                { "ca", "90e004a9269509986986dec4f13281c34f5e56885dcc34ee83db24ff87b28d3f541ca01021eed12f949273b75f5862caaed4ab12b8466914dae45ec8dba44ada" },
                { "cak", "86a0eaa243c2107085cf787b761166795f43f52874bc8201b54cd30c17ec69415f26be4c61a5ea4a3386fb9de9ed94e7447e1c04169be3aeda4bbc27b32ec281" },
                { "cs", "2056fb4e3168d0ebd511f1e4298d6f9165b9d7866d34eb5e682e8cd0ca92dc66deaadd80bc9c90b0dc5fe9b1aa9a8fd84c182447f89b2a6b60d1d54da6fe8f00" },
                { "cy", "b90e70db78aafc9da55d44b3a55cd510ba0ba6f9fc69526d261b1bcf27d5c8b88da268fabc923e406d6aebe3b6656459fce5b4aafbb1af23d53c93d6b344c36f" },
                { "da", "ea20266e326269a9ff218a6b005a78af752a7bbda22d0e88e47a9e19612aea207b64e7dab56b3d1ed40743c0da43c50fe9d2ac93a980ffedf2e796587d2e859b" },
                { "de", "b717ab9efa5e4449bbb85479d41c63a0324b99db69bd138fae1728d8bc128b25b432bb5a84a0a5651303f0577237522f645f4ddf2fdd0920250e85af54f367f3" },
                { "dsb", "e15c92df2c7b4d9c2a4c9020b09948db3d21c2b8a5ec8777a98c17f20862e9916ef2a3e2a13794f1eb2eb8c7dabd4cabbbfaafaa27dc01f9df93ff59f7646cfd" },
                { "el", "3f9d75ddcc7ea0cdc590974dcf72852944ed23bffb7d4c4a6357dde03e706f08cc907890ab149538d80b07d5b4f2249ff6da12b6d82360e7cfe7a8c503e584cb" },
                { "en-CA", "313b4bfbcf29a2d176c5a709b250642db1e31d0b7868cbbf9ff02c1cc06c00bdf18384af9f419d7985e72a44346806b60d316f8646e0f99bef6c34814f32fdc9" },
                { "en-GB", "730c9a0e69cf388142792664e32bb77c7390c075da1c5d1006dc4dfdb40197e4d6eca95d7b7323d0e9b0cca8835fec488084d0c8d00ec998706318bdaeed3afc" },
                { "en-US", "acb5e2c3db919757aa64379f0135173e8e45ebd10bbae474505f07f1c827d030f6520dbc833a4d55f68255312f08505931ff50d96f5780187b37abdfb4a28e3d" },
                { "eo", "aa27aaa958ce40b6a679172e7ee26eb1faa2f90696b5e0bcead6daa31e8bdfa9bc8f0394e612e3f79929005ada499ad557c9b97e861fd497b7efafe640e623b6" },
                { "es-AR", "fb0016b3bf57763b93dff14543261c2a04ce10300e553b4fc46cf12e39dfe5875ae7099fe554ab4a7993cb6df3d122b1f9e68e36ad73ecc3e0712172616d2c74" },
                { "es-CL", "7f2eaff6201bcaf7eee1fb5f3a6ee73f9b8f07371653a5990d1dec23b1f8494947e19f13ff26ec92f9f1cf99140ba6ec3223ac6c74174b87737cef4d3f09a9a3" },
                { "es-ES", "6e8929e3a5bbacb835ddf1e77cb82d0a4efcca4ecaf119bcda7bf97ffc89e7d7173e16c0fa768fa2ef530d7b3c9824b2d950166ae082813f8864b93b1d1be1f5" },
                { "es-MX", "fe0fbe8100db14b59b7e8c0f089a8e61733ec5b01dedcb8fcc22f8a0e78476e20d4d75d9bf34c3f8fc7f84b49b300a0bf5c669c042ad9c9f0f0a14f0dd4a9b5c" },
                { "et", "a60e6d381c640ba24fdcd252ed8386d28a60b6b70a6185025971c421cb15e75300a5fdb4f7d1fc9a90de5c2ae5de4ef9be31e7bd49ff659564b75583342d1251" },
                { "eu", "2b1dac72c33a98fe06f9494a5991d6f7b15c12dad61c78ffc80966cc3437ec068629d65c80f696816caf316a54524df765a7d53bced40d06d48ba424661fb448" },
                { "fa", "d33f163167c9e527d3f576712d700e7194087c78784182644a1f5c41a63c82404daae06122296fa36936548cf1038b9ff548e8ede0f00002769fbb5467f55a2e" },
                { "ff", "c8419fde56ba573e04d3915b7687204625b48282bb7524d1c7882514e3b58ef4948493baec53ec24ccbe9fffa9435bb317873645b9dea9c2211ce07b7da0d7c6" },
                { "fi", "1161882e8c6f6ab843f4a186f1965e3429b16cd301e1e4532a02f949c660f23e5cbfc5c1aebd609d5283fad02b35594dddc4052f004e7b616848f00777f28e06" },
                { "fr", "f7e298c70e553ad009f14e6ae4960dad2871cdad17b4d55b3c0888cdb17d726e3b9d5832c3884be2642b2a27f5318d653e1f1b80a7ddb54e17ac562f64e58bd1" },
                { "fur", "31d1217b50a1ed7f22315af33a476335bb647d3d2c70632ab3dcca8f8c3e0da78a76734fedde5b7a88021582e364aadbcb09d2ce18b84a86dc6b754d03c44057" },
                { "fy-NL", "ee794f0d04edf80180fc6061ad046c1ddbe3d66a3ca44a250d8f9772ac44a9d8fce9adf14d91c7acb9caf893e2e47ca5a23e510ff9ce231c855b4b0794abf72c" },
                { "ga-IE", "648596dec0575a2d53f9835eb069a44cdaf6c6758ad41763c089f43954012fe47c3689ff73fa27e791dc61c1f2065ccec44a61282e134907c63c6d0aefb3b8fc" },
                { "gd", "509ec341958c0a8983fd8ab612d99f06ef454412c9ab42f96921743ab76a04a79a707fb76a99f6459032ff21dbf8eee43c9993e9f6e1805167bd86e1b89f5d69" },
                { "gl", "425d4abf868c10d047f550779771f736cdf6c5747f1a7e2fd7b3b5591f9517416f5bb474aef665ec07b13378c25f808085636ad6a169e06de69065a2159a4bd1" },
                { "gn", "a60f9df3ce627d682bcd7fbcb932572b4620be01c00e67083ec1d7527c75c0c4135e90ce82055b420ce710c0ac81d32150d5c917c1da6f4edfb30fc156558dff" },
                { "gu-IN", "73d33dd5c45f050976d1dd88e8b334a6fcc86f5c16fd530b439bc2c80556a2d8c49b1ec59f13ddcdde30a21a6445694f1b41c55ae8fe871d79bf9ef67ed2ca49" },
                { "he", "33fd93fc8530c1323a2b8e1bacd557fe391d2b5ff2463b616960d9c2668cafd9039aa75d9dd6e9c713cb74a84c92e6779b0b9c06ff67a0db029becb54c43077e" },
                { "hi-IN", "3e9cce6f80929296829535230c51491e00c1bfd6b74a3333e4738f36df4b443739728ad7a34c9d7af38853f16ea6a504d0a4fa0b3d6c471eb581178c9e28fee9" },
                { "hr", "e52a9aa68f8264b0b28f1246aad8ef6ffea27e1bc8c3dd495b3474d952e6772718897fede8fbda4e8eb6d4619a74d32d1d5c7a302113fef1cb7a24673146a1bf" },
                { "hsb", "fa323ea5ddb5c709bc3fa592b6bfedb6d7f37db8c072f995a16314b0a1dce91deeb6cd9d6078bfd4accfde6479ec4dbb6077e5e58c14694d4b97e32cdd5ef83a" },
                { "hu", "1308592254ab9fdb155b229ed934c142c53760d8f5ae5da8fdb728c1f66ad8a1d5b94c1d5530625169c568ad8443782a4198ec98165e7c3cc3c243cac0b98216" },
                { "hy-AM", "f3c2369b95f30e794b3a08538b68f75654d1446edad885455a7766c8ddaf17bbd8cbd315ca1a7e01299336ed573dc7b512784139603b4b5b328c275d33eb6a55" },
                { "ia", "d427e43c1e8f9b3e42447ad03ee413a4a40849322468cf5647233332f272a87ba011bce69f120bbd4addc0b581bec7b6773416141bc76e56b666611a298b0baa" },
                { "id", "0ad91979c0a6093e1a95e0ec75319ddafe3a168df18f31ceec92cd4a23338da9a18c855676047bc4aee5ee3c547b3327a0b3e10f000427faf64f5350790b7727" },
                { "is", "8162a902ac2829df23999538ab186b624036d95984d6a9b1fbb7be91cd71391c8899b31ad428915f5f13a235fca75fb5ce153d855cddeb6c961c601ff07fceaa" },
                { "it", "9565ce3e7bee73dba5efbda842c0688821989793b340d7f97df269ab48f8497468520d43e983b335bd9915ff696e649fb1b4f6e398eeafc0ca2021f9906ac0b3" },
                { "ja", "3c0295932b97ae65c954f3a525faf4782da5f9f9ad40990ecc973feb7f982a0544bcf40433efbef68d3fafc92e68a881c24498c5cd7ee62eea23b85edf4288ae" },
                { "ka", "199e1f82341972a28cda5c50ccfc4f74bd965e15e03d59d6d015c42476b0ce1d5e742eb90b1bcaaccbd59620e7c0698254571417ff35b6cc2d092ba7dd55b91d" },
                { "kab", "1d6895293a55ba92731b883d76ba72e7dce834da1dcbece1d65d0860e69548e991e3c67371fcc0f82bd2d692a8b4f53e69946f37cc075e1cd051fdb2b9afa585" },
                { "kk", "c5c1a86fb2acd5a42fa32726ab9b815aee80a2072d386f5760408e1bce94faba8b0dbccce9f24f6211e8683eea75baa7dd0e2bf0994b8955265a16a40409df10" },
                { "km", "737f28940c6020f10a906c948063b9cdf6d0be76c1e5dbdf62d9e0b82b0a2f5b6e4cc9b622d683de31aa8966ffaef54be60ecaf25ecc71ef618d43b26fa59a82" },
                { "kn", "1f55e38f548db534a928c8fdeeed4649e20f900a51e4b46316699d37ad769129caa617ddbda246fca3f297801be127ca3ac084ae69a6f0fba1654cc6d26d425c" },
                { "ko", "0a9821d466f6341d2c4744c8ac29c92ec98ed29621983c0598e4426ff8c7b3f18ff770d783dabb1ee7cc5a55ff5ac15250b9469bddf359a47c1ea5e7428a3eaa" },
                { "lij", "2c18f95548d225334b1e2c2858de34bc0eea35fb5a7f5cf6f2795251d90b825b0a71b22b788d3671fc186e48f5e5b09ca403ca0635b955cbecacc6068eb8d033" },
                { "lt", "b4cb895c86817a3add14465b40d98fdfc76825dd4e28feb484e72ac6fa6971e6bb359a8cfcbb83d3c1796c74726517304ea562f69377bd145e5250e98cd89724" },
                { "lv", "8a3fbfcb0d06ae1d766994fbeee2fc790cc8458a73fa01966085ea63ae9027ee5b9a89d5dccd65d2949cfa2974e79c5f7b6d4ee68b3b1f1f61fc4be65d479ab2" },
                { "mk", "006b63bbf637ed893591a8195cbf1ad550043601935295d3e62a28ef049335d9512b8a711ae35c40b869ee7d795a6e9fb1776599dc0c117a3e441e7a72da6905" },
                { "mr", "d6bba8cbc24f1fb6aa557856f10d27ccba125495b03aac94b52659c5fa9754751ac2c60f72ac0199e3b320c2ba8f18e1316f392a5e3bc31bc201e04788cb5dae" },
                { "ms", "7029acf786780f6a6bb4487f036e91ff38ca3912fb2d8f25ab6485ebcd63d40387de07e556b8d9a891dbd9655294eb56a65fdb3774704825f51e5c13a5be79c9" },
                { "my", "b594efac161dd44310febb09a4e934d327760cf5bc7ee2ea06533912f3a6f92b10819521d48a9f62b604cc1791015f3f8884b6b396d9e588e52e48a74091a2ab" },
                { "nb-NO", "cf43cdd52ccf82d911ec20d6d960abeea4c1e5c58fd79757f8b03b2ca6ca2efc1fd3f55a00f9460cc12dd8059d364301eebc73ca1449e82d7c35c03f4e8fd303" },
                { "ne-NP", "ae4da7d1ca808bd774942682c77698ca0fa78e31b41ca655c4ba5342a36b4b947f4b4ea88d443f2a3c9f1b47672bc7fb88e3ca8561556df79f89f5aa45bff42a" },
                { "nl", "276453eec48f254a00d04dfbd2c40a23d7346fddf3bc43076740bea3adc5fa50a8155004e8045d113c264b4973ab14d0f5b2b6face0ea502448e05d14e58b1ef" },
                { "nn-NO", "70af237be86c587860c6c3e9148c475de01b70807f9e161e0613719b608d621e1cacd48faeaf20f9166e8a220acb8ee644887db628ba293bdbf466708153916e" },
                { "oc", "47b9484f4910028d9cd54ebaba5f4e3f720a9c4646519ba349ca6df496057e1229f569b954a197a58d058c56a43bce8961bce6dded4ae81f27b6a318b542ebf4" },
                { "pa-IN", "4b2b71f452ba62d66dad1f2855869a583bc88e5d9b01405e96527b5cdd50b5d245a035e64b18a8dbcd91ec8fef317089154d7acff4d21f0ccb7c40cee757fe51" },
                { "pl", "a11ce5443787dd69c14d20b369cf38f183dae3fad120e3b336f4c59c31152b41b63e5195ef26502a52b7446c5a6e5bedd9146ea832d4e016e86f117752234fc9" },
                { "pt-BR", "bec2607c896f6c761348fec8ef2a4d02160651b4f8fe04e01b00e30459e4915fc9ce1a4cbbf48346c5140ce31ccf6cc4d77259c50bdc2370b47adce131de3961" },
                { "pt-PT", "2b2aa24688d7868fa6f1fd7adf9bfbd281945dcfcf38a5f8ff3694c96f8a5cfd59861ff352cb5ac75daff517e3ceabf574ff0d0860eeca285b99caec588b8d8e" },
                { "rm", "b934f0b0c60fed58ea836b6e4d55053c21a074585bfbb1ff2cfacea82945089a28f0a28484ca42516154ac88d8a40d3350d390d4becd53df282151d7674b78de" },
                { "ro", "ea8a6ce157e67ffa6576cc89387f87def244c24032d3deaef8147b95548b3b93150e1abf5ea5867de602d1d04835d11de5ea759af2e0eb9fc21c15fc615e5b3f" },
                { "ru", "c75d9fb5d87d9ea1b5a2e70ee5b6ecd99362c41ec455ad730b9809089ceae8a1538ba8a21356050c2e93a99cf94766c41837bcecddce395d3c90a0051f56d815" },
                { "sat", "b362b518175d04a0a88ca4547bcaf0aa62f1d83cf674c29602e20f520d3248b5e049093f12cfd3fa9e7cc6db5b72a1c9a4929fca6b900ca4a2309d0fe46fe2f5" },
                { "sc", "3ea76d83858a78020d74110b5857f88322ce0316d6df0fa06288a32c45788d6ed3738496ec80e92bb7b84b1966cfffbc1c8951e033de5327ccac4e7d0b5cc772" },
                { "sco", "fdb432d2ed8df265c6dbb01ae7c9c5813568b5043ce507420199d2d9a2006ffd51da86b32880e734f8489ee5d407ff0921dd23a322f00fa3acdbdcfeee310637" },
                { "si", "478f0c7f4c84f8d17c11fced72194686e287ff2394e0d45a2712f522534dddbb061b8f17eddfee250993ac7356e0cf96443fe6e4f9ac4c4ffcd838665ed9a825" },
                { "sk", "92a0803c403e512102fba7631004caf0d5070ded15234a03f2a5276fe9380fd30b226fcb594c563ce75cc708e6e8253d57bdc12495f80ad8fcc51c9aa717342b" },
                { "sl", "03bc910836d88bf01e7d79f614a0ec820a13e5d2e0adb43d9aea8ed718a3809c811abe1606da7018e9ab364e5abcd6f788fb264e968e3262b3b7d9eb7f9d6a68" },
                { "son", "f368d124d8faf18705623ba50a8dbc219a6cc94f7c3461557013e06396eda9095be2ae1a9f4693401181e65f0b2410149f5f65b00b532225d36d114d60887722" },
                { "sq", "a767bccd763eecc8d26826afbf382d891e7ca2e69c123d5077f563c6b43e795fabb871e11865b709efbb30b2e1a0916baf3b96965f16c2c348e731c9439a810d" },
                { "sr", "a271289efbddb4557b0594b6ddde56c06ba3ed8ceee43f550dde6456ac0366128bc849729e26c01aa982057a989856553380f30bd87d60c3e38ebf5c35502be5" },
                { "sv-SE", "005345051b0c4f72330a437ff0309b91b7880863748def5052ccf100d418c9835126ed7980fb3310efe8e938980cc14523d1fe313ec3eab125f93710e0dfe6e0" },
                { "szl", "1bcce9e977eb764df1498de12a189565d4cf5b277f7e4e9e45bd434b367c8d74d4242f8c95be259adfd4a1a397d18ec7a06f58bf5f312e167339c2b10c4fc58f" },
                { "ta", "e1f0fd0a9c110471196abeaecfc5ba8786cfcd29e92ae6c725335bc6dfb78f60c4741eb42c14fdb66e92735fba94dfe56a520886458fb593045a98930781c1ca" },
                { "te", "116c6df7683cf5ac8b8c1f56839503a8d7068e022132f481e2a83d496997c9381ebdfc2fc3a47fdb1c8736cdcbd2586a391b61d9a4f7c0ac7948d1f22502bdf8" },
                { "tg", "5361fccb05b87f3a49885980364a85ecf79c5e0ae2ae169ec5ffb7243aca8345ee507dcd370c43d2f139a184532a14d55e2cad7e419ac975cdb010a4b3b1e799" },
                { "th", "a56af595e6d0cea2b78972e0e624c5b12237ffae2ff11da9e4fc466c4f475f1f98306bad33c07def26261ec1bce4f4dc682d90ec2c8eaac951e00b3a05f03e42" },
                { "tl", "5019f26e6146399688f3e1ae90a4203d9dda9554ddc460a11ab86c3331f9832ed5ef793a23c53570ae8943ccfa93aaff662e8218062bbfb44540fce06d492219" },
                { "tr", "53c941ade733835caf5cc6ca1d9274e7033afe8b7bd7de1d6a47976925cf5da880dc0446d3d059fc7a1e387000d1463f63bad1e1084fac4f020d6a92666b9cbc" },
                { "trs", "36f199fc2ebb9a089d34b66bf012ed0dfee141cb922ae01a9fa32fe21a9449289c54d7899afd59d127618ca107b3f39d35e4cca8ae98daedde9de288e3f1e1a9" },
                { "uk", "acde007f8b39497169c8ef6e854ebf5f414e7bbd31d47a6bcd98c9deb6f23b01658bf2de81414af5b031a9a4cd70d5ba260ac4ab56fc927fafd9a40263e21281" },
                { "ur", "026cecfba30d42f16b591dc288b675e83db8c1d31f35115b2f115de2d58757caf1ece9ba1ad0f2a446d8bc606349685fdc1e64663f0aff77536fcd37f7d849a0" },
                { "uz", "b5e92b5305dc5d9d265f0f8d63b53caad9102b2655305266668eb36e89d1bb89f91a75c34217a0c0ecf7ff46d6a876575148127911bc9e90a4f70a5c480cd0de" },
                { "vi", "4c0fef6c5eef9630c77afdc2f1b12315479af2eee27c4ac1ffe99f92bc75f86f5743b73d596aa6d07220103d763fa53e75d200c2bfd52a8e6e6608d8c53054c4" },
                { "xh", "7f3c3b0fd1b633048e35eaa66a79c349a4618e5587b78fae6dd827df58a328bc687da550851ed08a1f96b0ef80b7077b024232304de70b64618f4536f4e33682" },
                { "zh-CN", "f9db1b292a20a7ddc7879c7f67efd4243811398a95e7160276bbe27a35c8b0338c719c8c1938c77b497d96ff04d678519c65f32137f473fe821566618a1307d8" },
                { "zh-TW", "dd35b8fbc0d6653a5e80e6897203f8445c72a259f147016dd2d4b3caddfbf0e1445d7400c4ad628d1e2200b6b620e0d8d9bd97de0d9f34811dac187a5bcd555d" }
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
