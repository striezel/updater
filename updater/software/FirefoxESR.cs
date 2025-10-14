/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
        private const string knownVersion = "140.4.0";


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
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
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
            // https://ftp.mozilla.org/pub/firefox/releases/140.4.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "22490dba3c3485c8d095ed26e7975c5c90b34d754ffabba3c65dd979912e43ae3eb35baff0441040b1e6ac3d53026d93752aec353d92a0f6c6a2af90b242028b" },
                { "af", "81bdb0716ab83bc9c8420f4714220a30c9b0e588bb6df0a3c4a0ebe4c21a4fd1748f11288cb2277b0db557db6c9f2042ff25fe4c00f6f309d7c12bcdff75c18a" },
                { "an", "0353c5e23f2341183bbab04bc9fafc1105e755f79715f5e40b45e220748b85a11f9dbd02592b91f3d1ee71d1214f634f8dea551187651cd7e1c954f83fdac530" },
                { "ar", "8df289b122ccd1ac53e948ff67d14c78f879e13d83bd3110537ed7835da83eea13f734d3982c0b68a56e93033e89b3e8a1f3eba578bde08f79988c5516322178" },
                { "ast", "8f8b7f5bed4667931b55dac4091a73f4678e183b279067a5c9952eb900f9fe653a0f40fe4cbe638c8c1cf90b97c3c523eea13391da4f5f09ce63b0209fc657ef" },
                { "az", "c78ebedb7b5e1f6160457959ada7129c30c42eae2bbae2ca34a74654aa0f6026a2ea11017613d9dc024ab7593804ea716c4697cfe82cac576cb814d670e54f64" },
                { "be", "8f8697d012c102324c1a444e0dc462cd837748e4bdae393be3c5877b204fd256c14d2e1a418a18ef323502f84ab148996b2115e8a88c3955731b209672d447d5" },
                { "bg", "517b917eea8d6988f0232d26f41bdb9e6b2d33f50cd3bef1e8e4cc82a01de3ac9e872f8c67e9264830b30a447080562347408b8a306b3b983155e68415a3ea37" },
                { "bn", "ad8d04e8da6bc2e383af468325c482ee794ccb73baa14347a487dfbb14b2a3641d3cacb4bf8b5865363255e240903f970fc744b9c98ce559b950759fa7da045b" },
                { "br", "83594eeb9c3b3a3bdcceb246cb546cf56473aec72c8e78c2fb6b5603b58fca99207a1f76780f4ac2ae0576514cfae37231049de276d40246524bca1bd34e3b1c" },
                { "bs", "c46ca6c35fa1c30a18db372496d670bf654124818fc9d37dd23734265f92b0e6bbafc7af0e73b67de7c39eb7d4d798732d4969ea17c1cfad3a12be73012105ae" },
                { "ca", "62156e67327e30d489332c78dd48389c91640e8f1458c52376364e33c0f02169a205600ae9113fbc6d0ac5ed5d81aa651abf73abf880fd432401b6f3bdc8d400" },
                { "cak", "9c014eb33c9c87b2f534dc1c1af91a382ff820ee463280e89da19c8c8e47e86869041fe4b97ebde15b7cf7361c126ec74548965a436735f84a8ce9c475074dac" },
                { "cs", "28b8c4dce100ed5161f729eef1874216d153f203c6ffe02ab46cd3b0c73c85ca4e01409418062abfd61d652fbc0e1dc42d74f3c3e91ec1cf12ba0b4ce2f858f9" },
                { "cy", "0749a65c3d575da8c393daefc2e9435dfbdbe12ff6b9c9918130f76d2432990d316989a08aa7011d9fa48f1eab5e35bd09f03c803885f6643b2b6cd4faa44f31" },
                { "da", "1048a5c58e0435a049d5766326e69f3a2653f7fdaa05f06fb0a8da1f50353c3553f8253c48563411c313871236cbb06c80652824986ba2d1d8d874d2ec18cf14" },
                { "de", "f79535b957fa9b93e0ba48f2f6e984f53b74ff3754b9bec14b3a350b933a94e2f7fd947ab2153b5e2b98e3c09b3542a5a963a760a03fd24a2d0e498348a553e2" },
                { "dsb", "66f37007d90535f666bfc650347ad523955d5b8ff1f2be1a3a9a645b7f981e47edcdcd9ea02f4167135df59214e786e0f0755de15a5bd0de09087e0d42124991" },
                { "el", "9131098faa19d63f98a45983277ab11638fe6e204de9dc42539b4d885ad236a2ff567b623c26be83d2229c686afc48e445f793d529c62e5948f17a4481f3aaf0" },
                { "en-CA", "e49c365380ec6cc5b303db05487e66f453a10a9c2960df573ceeb02d2e5f0617ce507c9aed0460d42675ebc83ebd856bfc23871ee47778695cf84e1fd6349801" },
                { "en-GB", "cb9855790ce9973b2c45116488492d5850c77b3c239c05bfd90611b41c0b48dce2e5b263c6efa3f07ba3f7de1c20f43d3a0c72ca31f3684ca77e214e9e9e0793" },
                { "en-US", "4be068f1168861f9777ea16dc6f6e9114530be5125e6157417aaabe2c4e5dee98eabbc855a2c41540c3f6d99e6080e76ea613c4fb34046f1a370353b0a75954c" },
                { "eo", "3471e2018e011c9bb018c0730cbbc537132f642d0c0f74f0bfa823404063ab25a894b33fc2b510154ba07d38b3635373ae5501f278cfc565d1fa53b598cbb907" },
                { "es-AR", "615ea6a0de94a95e55846a219c2ea3b3307bd6d3d9176822a4d19de1126f4a74637ad93ea06141d08f30defae682bf54775ce7243ed133f9373ec957e23d698e" },
                { "es-CL", "19fb3a6c155dff30f4e78616883a13455697c843007b2e34cadf5f2ebbfbe7dd71dbce5d7c72f30fe0e42435b85db682263e34aa3c14683987da717bd6eaff0e" },
                { "es-ES", "076a7845ca5c019b22e773edc0933f97cc103c6fc5f80c2f25350ec819396c6c76d8602765355089186332ee2911eb5a243f91a5f67b53dc043e035a06833012" },
                { "es-MX", "b2717b8c1b3e62f127e0e6b0f225cecbb28a00a115b826d0c023136e738c27c91528d24126855307f1ab26c95618bd4dea1f224e73b6653e73c722839ba95d50" },
                { "et", "0c30bbf981a88d8e32216378a1b11eead5f26e7dee82b178f7e58517c1fdb1b5e013556cc3ebfc469aa51aecf5becbbf3735293b594116e1f844a2a4a37a2413" },
                { "eu", "2323ac0c0e84f06a2fb378c4c439f04fa7fbac4195cf73cec01f419833af9ab66ef1a29747fea77141956e6ae97c0dff4692164058cebec37699d62e6c8bd007" },
                { "fa", "eaa9f134a63ffc0acbcacc0f86ff3dc8bac9bae859f06d3f66ccdc71c1fe93fc6c2f1a71ef434408cc24d1469d2c9e8260bbfe4346e2decd526d44848cad2545" },
                { "ff", "ecba31c0036d6de62363ae0fcd6b511a126541f017d8ca46976b635b850c601718a4fbda3dff503e1591c7ff876d8681ff78341936a19b6e644d80eb57fb2e82" },
                { "fi", "7c3303fc2a57d91e2407dbd8e6bcf579424570dd3a3d97f509b9f6a1771df0233629d4c8d80389cea7f77864e2788f58247748b642c63ad8d42006322946178f" },
                { "fr", "1778eb23e4a1e0a14d3a358e02dcd604466c01de73c8191950bb26a238cf26d8b0f88eff53fafb4fdd73eec3917fc24bdcc025af37bd0cc6eea194caf5823ab6" },
                { "fur", "60a506abee48117a5cd4bb436ae21a238ed4d2672d71bf3bc2ba056c2fd70963ac1426f8d9020a0c90211708e39034c029af739cbad6e5f65ff6e77bb1a27a3d" },
                { "fy-NL", "9d2c0fafe859c80ec67364ab0118436a6a8165230f42e731a4900297c9ad5fc7f0367dcd7ec25843d468f6d1ca3d22d76c7eeb0fc0568ec65273b0e957162d8b" },
                { "ga-IE", "a86bc1866b3efe42ca0f7ec3481fd4455bf0f9a9f9f2229820cff114828521dba86cd42c4de0e8ec9bdf14025eb1a43a41fe3137dd3ef82f9fc146371ab29ad3" },
                { "gd", "e299c3dfb72b01e6e8daaf1597086863c9dcf13741ea1308669473856a188cef43355ef48f6466b0173388aa2f6387fb5dfcadc52acf5af0e729a005f90ccfe9" },
                { "gl", "da5172ded638bc01912d1ebeda88014f2ac63bd5664e24634f21f8bd84f491d3380223564293865314829efbf4772a21fd4a9b9966f039e8b94269e34137259e" },
                { "gn", "2537a0dcb3e6cc078477da61bb5f4014e146cc14f7c608caaba176152a18ddfef67a71bbba860cf508a57ce9e6a9744d01f1015abbeb5e0b26ea41c2320988c8" },
                { "gu-IN", "e911a8815a14ae8c8ac459e4058ae8110c9c6fd35657d533a4230742ad1dc3f13a19d14e3cece2bc7bffdff0fcf5a36ec891e282cf7379a85c15cdc64bb7b5a3" },
                { "he", "d9fc3993795182c1540ebaff9df191c0b3797ca1c8678f82ca76f0815a79151df8850b9021da23dec6b7444416e84e3cc6f67b5e87871e9573d31c0100cb19b2" },
                { "hi-IN", "ee6363070586639bb2bc7ea8561d6b3dac3c62be0b2ac41e8d03476e91e32df27ad1f603e55dfb2547af42150373d9418b0ea071fe0531aa56d8796f3d40e230" },
                { "hr", "a061252a114fce3f698a26ab83a2024f7dd2f36f32f07d52eff29dbcc538eeefa3b9b7b760b9e38a40caae05c05f026c91f0f94c16f0b512a462b705a379ca58" },
                { "hsb", "0e3914dfbaece78a174b648ff1b81c718b31f144df17ae1c226e396e3361211e099b7f38a58890e326b900dbe62086d92d137b0d9ecf2dab471133ecbdbdd5c1" },
                { "hu", "7480c469ac6bd9d504dbd72bb8f772061c6abf9ff3831e6425425744fd7597a8efb65af8e0bea84e57b1680188a21299bd46047ee1bd9477496cf5400e527a69" },
                { "hy-AM", "30b353f4f71c5a5f011e288b18e32f81960c2a217cd7a91e31e0c7342cb7fc55ba83097c8c43e53739a310dc7bc1492af17c6dff79f6e558d7216e346b0839f2" },
                { "ia", "a5184aabc81f09ddda429d6aa8b5249ee11247b077e76236d55064620768022b1db6cf439c76439b84da6d63e0f0b94397bafa5345a370820cdae0a92f02b54f" },
                { "id", "9391ffb275eade11454d1d2bfb1412877c6f030ea6758c2a4e362cc0fb6c45dd2b05c3f40653b25f64c1f7d97e093e459fa5033b0f800a8475fec29b5da4e0b7" },
                { "is", "e577e8bd7de08308c54498a1620ccddc0f1a01cf4d4f4f91f7416fbdc015993d139120bdb7c8dcae4f3c8f225f997c6f948fe7aaf50c555abe417e076297c102" },
                { "it", "77212c5613ce1898a9d05cf1dbd3482899aa7dea767e4d919a394ca4fa75f68154d31356b68ee14dcd1b9ae853239135377e3683dd59bcc216b60dd7d934aae3" },
                { "ja", "4cd0fa9bb0345c58d4992fd489901e7903731ef4f2aac5e40cd1ba1b98b0e1472eb8a38c2b73313348063ac3fe562e3dfc5349db21579e27a065fd02ed5b2dc3" },
                { "ka", "5e1423c092b5f2d783848c7f21055e1767983dafcdef2f3f469846520501621abf33216a7deebf3d5e855683aebec8c722222e3f6ada3630619e4bdb676bb270" },
                { "kab", "9e4a6d5ce6bc972d7a15714434fe033e3099aa1b199266c592819b1f22c090f8d6dcf553094cf8a7afac30f37968e890fc35e1c230706db88d7497cbb66e8050" },
                { "kk", "b89b40639ec44da922bcf454440025ccba24935d784c606e69d6766b509efb59388bd41eeabcfe6edae9a508cacbacba75a4a1113f62a202c79e296bd114ea28" },
                { "km", "a33011fc780daaeb454c163a228baedf633ef653874688fdc69cbceae7027da1477b46286aa3295c7810e755623607c70fbef83c02d6ec1c43c0cff6afff49b6" },
                { "kn", "ab2e65981ccbf78089c7ba001209402ebec60069b3207e71e217ab20b52feb4bf5369a5df3a48f40bf3800c7c82a9b255f5bcfd544d97e551024e21bf338a70a" },
                { "ko", "d0f6799aee5bc4cc397a739e667b50a4ae864429cc006ae8bb91aae26c0b0eb87d01ec3d48ca90482c322f98b09546da3397ce315b4841457c9ba978e760f858" },
                { "lij", "0cd37be479cc6f646825922b3602fbb7b313800cea38632d2a18090f04c68217fe8130986740a611151ae258cb4116d4c62764440daef91fa03bb32dce6aaed5" },
                { "lt", "915a0a5a9f632f2a6a2ec8c690cc0d4fad894f34388aee6a78deb317e6808275d5a37599361fe4b7b745c6d8fd3fcc49fd8bbb81a05fc3370aa704866a0afa71" },
                { "lv", "636d5d2f06770af9a8821d08db5766054030792bc145cf83cc347ed044b97acd3fcd0c7e0430f6664fd82a4cf28d586badedcb36b497e9106cc7f4637d616956" },
                { "mk", "83cf0d91f04a1bfe7279e80b54a59a0e1fb208cf5e3de7280dfc67370c24750aeb66d9c950580feba903f2f5f1fc94adbd1483524f4923264411b0df403e8e45" },
                { "mr", "74dd2f2a27410ce4b20ffb08456f20ea1ac63c07297eeefb5ec2b000e9deae00548a1ee2e6153416827a226f7ad0049e318e201ccae7f4b30bcc0907054070eb" },
                { "ms", "55291a7d0eec58e5d86830986676345530daea94d18721d1c07de3a850f9f175071b6f3f224c5f769f0a196bef36f58cb8d8711d430936c7f28349e83a22dffc" },
                { "my", "7e807aa0d7883b8fd363046457557d9bb556c19202bdb20631565e310beca014d3956bcebe2dfedf2bd3d2a3e43db31ff4a3910de1bb122d67ced823fada9b9d" },
                { "nb-NO", "5ceda53fc7189511e05b63cb967aeb3c3c274c7e53486869697bd295d47d4a7f72e4cd5451b0ecf73b2de5bf2b2b065a2959bebdcb3f681152f58afee2e1c652" },
                { "ne-NP", "486a11f23b059be7ae0137f049a039efd69c99ef2c205d4b644da4488ce525adf3b617d28878208b1dc7e5d5ef558c92526d5f7b1829fb0981ecd01279e4f064" },
                { "nl", "e9c56a0f0b6112e66a11aa60f7454e47f3587bfd1f884e903a6591caf0fab24c05387ef6d2278eb869c7dab27139447ac3291fa21abf58e42476c0b849d103c4" },
                { "nn-NO", "97ed4b742a3eced84175ae9b1a6511bfe21d74466e1c5bb23fc3e9d81f86543879c69146b2891ae50ce446cd20c788d0a9c9a28ea04f8a8f7f76f8d5390b6d45" },
                { "oc", "9c34ddf78320c9765ab58aebf96149fbdef76be85640d467ab541fafda7ec3aa48da7a4f7ec8dfad0c507330028088869d025c013842843f68a7b54b1a62518c" },
                { "pa-IN", "f2d814aeb58d4d62e262c685dec4de4a3746247255b3d768a42e358563e07ce8685637262db0fce1a3fcaa94f1be7955437bf78ba153a14b9741f852ce866334" },
                { "pl", "3d46fb07cc20feb7d4c100c399cdc82ff288b9e82dd28e9d101d83c2fcf5c89243f45dff2768ddd833a4aceeab59e2e08259b25e71e60ae7749d763e957e419f" },
                { "pt-BR", "fbb695457b734c98b5cd88c4e0277e9ff51eb37fe2822fdef775959c16f81a6ae448294dd5bdb5f2d669ccd738370632c2b28a34a9de0e3687d5dfd2e2b8bf81" },
                { "pt-PT", "4ae3586d537267d52c31c46799e0fb0f618a1bf9c9a36574590b409e3ba3873cc6a1a59400dc0ef374f2cd85c29acabf43595dd3761bbb2230a5e9ba3dae4a70" },
                { "rm", "0aeac5b3bf425c79852d6bcf086ac8caefc794534cb7167c3a0cc96b499480cce4abe80c6c19fd3ab9525683522c63377050a059206b1666aea99bda274cfe12" },
                { "ro", "63296df458b4b6f6814fbea8efa153606ce3e0654e4fea63b714027f0a678a95bd3f622e39d31490a92c6e6ae389a2ba2053c239d652451010233d6892f3223f" },
                { "ru", "aca314b6440f220f8fa57a13f8f411be6bcc483d4406cf78ebf1ad38d73adb8d622420e6dc9e919d462e16fc0d5bd845cb53b1642f5b22202ffe718f96114d91" },
                { "sat", "2dbe0abd9787b316b2574a74916865429d378dee1b6f59b674761a682c7209d5ec67fd9a986c7e4bd22be3d4b4a7508b65d7a650d839e40cd7cea9899639eae7" },
                { "sc", "14bcd89941b2348cedca1fd962bd01e8c1f6984230b5a6418d5d21bb8e79a7ca4a7393edd286c8a63fe917d087edd558e350fa6bd9eb482347b1dd89945cdbb1" },
                { "sco", "f7b791ab4dcf36c67a8967395764deee6ef5a170d3ccc3975ec44d5cdc8b2dcbdd78591bbae19b5c50ed22e8ed1d4841420f59991abfb7ee15d2acfc05e96e85" },
                { "si", "3722684bff3d6427e4a70ea23ff023c4c20e29eb8bc166c3f0a973709d3649790d51dfeca5c8cb2f27e7db69e4448c1bd2f0392d3da2f7433a8ae48495d64f39" },
                { "sk", "99aafb7d27e155cedd6bfee02eb3e250f4d0bf8133266497225e7216146994551a97796d12f9ee4121d398004551557c0d5710dfdac96bad37b38696b5ec5b7a" },
                { "skr", "e3f04d73e28be060bf0c1e21dcdf0ba41115e7729e7808f6ddaf62cb006829cacd482f0e372d64cd5922d024e2d0481641f9a920e732af5713b1f0e43c6df829" },
                { "sl", "2c913355f8ea4014e430fb0406334ad14579eddf3f5ebe089efd879da1decf39aa5aa9a6a945f157cf585e20e9de221d5b0be122ccd5d6c4070aee5c8bd103bf" },
                { "son", "8b86c3517b2066adb9f958cf0086caf625df09eb6885c4ecd88184243c7571bf96b2e4d32f50baf00609087d72ddaba66b8fe466fb64baf1299d86ab9cecdf86" },
                { "sq", "485fa8ace3a91080d4d404a79ed2ec6614de42071713a9f89a9a9642414653b23de8541ea5aed1a28a63ae6f4af763d19ab52931aef7a3886179d06e3ec8f559" },
                { "sr", "75aca33da374a67f636d7c8fbff3d0813fe54841f8b58b8f2bc02c2fca8155b74c673b93ed0145217521cd0f1a58b12da06e442dae8db585659a6ce0982037f7" },
                { "sv-SE", "10d447b26f0a913a204ce6564ded1777a1e7b6c104d8a320fb20be0a99e3ab0a6e5202f0154c19582262b27006a9183a1d15ed6e7e3cd3b59a5814d69bbb80c6" },
                { "szl", "b6aa7eb9beabe1858531b0dea2037d20d0fdb9207a1de557d0e7c5a0f4f4b4371d31d75a6339b4f005d821be48999ad4780106e18fcfae34005532e4a9b34001" },
                { "ta", "3ce7fa4d649dc693eca2ce418d7923113fd05de8bf98ebb1f9e31e7d7b082a33a03b05c82f22cd8a0bb1e92023b9e7135d31ea27928ba254f0486f26d0fe3170" },
                { "te", "6cc0f99154e07b60abc53094c5743a1f5c362e73ab5569571f02edd812e667d2d559472b720b6c6533d2a813859f0097f43d590d7f013f94cdaefbae0b2fce23" },
                { "tg", "11fde0e746677f4dc7222e26d1163ae83626a0214293f722b89e288cdc2c9811df8d92560af18a7dd618d835ed7da82e6c13d91c133b6496dc1f7e815a41f874" },
                { "th", "ce6b505705b4c1383c42134785839c7952e70cf3d4d289bc4b9eb6ace512bc6fe721050772e56a92c3604e613fcea5c2dc2670cf3c59727f231c5e590ab3de98" },
                { "tl", "2ffdde7985d49c25d1797b00fd5cb0ad7ca97b62eb70b7947518275b7a2ab2b6c7c59d5843ee1a8fcae39ac9b6d4289a731af099b82321c8f1d98e1758d26274" },
                { "tr", "f2f0c1e5eee7010ba76daf8ed45c712dbf349d64e131182f410f5f88efd8755187a96a649b48592adf6c3617e42f75cbc0d93313f194488d3a55eb4874c6fb0e" },
                { "trs", "858ee1ec4bb657f3d6430e46526efabf66814c2eb30107f5896ec4aec00f61dd3c3949de9d50e4bc66e3afb31064b4fccff63969d76b0638b5ec7b614fa0cd91" },
                { "uk", "4bfe95831677aa00ba13b526cd03868a67e90fc75afe97a368db2c1397ca54d04da1dd0b105540cc806253a9664b90896457c42b0d98542c270518586633a4bb" },
                { "ur", "b0d18ec1512c589cf4e238f26fb1a60f66a0c2f7ad6e505ca3e7355ccacf73c1f98fef6ba3cda3e7f64a2ab93533e192fb28014b765ab65e0e37f1e56020249e" },
                { "uz", "7e26311d66fee9f70537cfd1b878c80b2f05a0281b46057e09057914179acaacc10096a8a7c1dff03acc85576281a768e024d927a6c19e50c6e9fad9146dedef" },
                { "vi", "1f8af83cc444738ca48141c2d31be7cfe44886666687cf409945224c0a52c2abed0e68dae335fdd2e3d41b97f8d92ddd3e550eb8f897fbf8166dca53d7826be1" },
                { "xh", "b3f6b955fb8caf44cdac9a078c91dea1b9f15eb79bf9fc5f3bee724b8ab0cad311e716631016d8ab3be4a89a7859df7b79a51dee73e8cb5be42e5bdf3df03b2d" },
                { "zh-CN", "3be1cf300635ac34a852280073504cd1419dde28f414853d5776b9deb6392b9f3ba55c25063745cdf86583d99142efd0c2519672d769f78c253b8313f12ee366" },
                { "zh-TW", "68a91a3b3be2864bd9b528e2a2946518ac15168550d9a1a6d678ce4e91b8d3b3245eaf2eabf4eb1a9d0fd3fac8c1f47bfb5c0d432212556b5498533e1ee53611" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.4.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "755906bb258d86a6deb2b11d1140dd44dafd040b2bfc1af0e96b54dac16f6446b58f868aaaee1c087a227905381aa26b4eb71b9e66deea195c7bb59f091771dd" },
                { "af", "cfea3327e9a6ea38bbd9675431b944eee7b79d7bc31ab8db040b80ff486161b36d97df704d589844f2a4f9dfa409e4487f218da39bdc3eb59a5e7d59c922bd8b" },
                { "an", "0069a6d925b17683bab4713f40f6e05a1584811396e76835244c7e983e21c353537cb86755d09df8c5b159f24cd8f1b50266d076d2cafce5a855ac40bb14ce9a" },
                { "ar", "d2b361756ac36aef17383e502a781f2a44dc60ec7f78de30e63aff449147153877f6c1ab9f8342059b01cbfa7f86ac457895e298c36136e7c30173b994fd1817" },
                { "ast", "3dbba86989ef963e71556ef44d9b3eae3dd50a237ad9122a59dc314ff20feb7d3cb29da578d71b347f11495963dca897f686ebf5602c5c64ffa67f39055d6a10" },
                { "az", "a860e49104d8f9b66bb4905abd7fd676ff1f6bc8e7ffa4e2b87e374f1c20bb68c36048528bffa7a99f05e9d420c342a678ce7fd8c2fbbb2797cde1c2e2da198b" },
                { "be", "31891b0e7bf756f7ac1565de05a32217ec7e6254320be1525d047910e87b306ddc26c631166eb424ebed7d9b51b1d00090368bb296854b07b6f07dceadb28419" },
                { "bg", "bf9d248a983667af95630e43702f554ecd25ad5abcc9da0dd8d09ae431800bd464aa29a42929a16c07703be1f93fcc6b23e106bd55005827606a005a41d50433" },
                { "bn", "8bbdb57054f649be1b0a7268ddb90381a7bf4c1504a66d2526069cfcf4669a5a805da680a1efbc9663bfdaa94127123520a6acd95ee4b078205c348f73dabd7c" },
                { "br", "592e706061214cd49e2a3ad870d0f6ffccc0f3404e0c47fa43e7e56e37f9c870a435954a7c4e482b01e1fe13f1e2b34e059bd6fb85531da303c35b7deb91df39" },
                { "bs", "910dfff645c9edfc25dfe34e65a7a588493cfcc274417744605ba08e2e6f6a5a8ed89168bbbceff03d13326dcaebfddd6542b000faf43112c0362a73e9d01fe0" },
                { "ca", "56cab13834785dc06ab5b49d75751b4ac3e12ab68023b81ca81264f70fb70f47329967ea43fe4692bf1594320f5d79eb4efd99afde32f8aa21832334963cb3ea" },
                { "cak", "d2b2d4f6fd7778e5f4f70d56a008be2dcf97bd0993ff7005f5c4a2ee4fa5bbc95b9fc22e0c1772ecf2cfbebede84eec24e74314539cec9bbced6fe27133ba1a4" },
                { "cs", "b7b67c9b6b11811ec25ea7df7bf18ba743cc3aa74c31563c6e830798a10857f3e30738580f878161d1eae5d842774810c09fa51013fc8110687b5622492a56be" },
                { "cy", "76e4785ba07c87173d3769cdcb5b42bdae3cd35c7462718f9fd19efd66184f18812e5e274ede7fe97c4448dbc1e7dbfab2ddc7e32c0fa7f65ef3c444fd9ad30a" },
                { "da", "f5659594752201a4687a005f886679a6ad8a1891aa1a7984bb14db3413bc7ae8bc76791ee38bcdd3730c460fde9ce88ae63325a776e7e4f4131f055bcf4e8af0" },
                { "de", "26d4f5cd7e709a32c84e740010b39a8b132fc0a771b0c4908cb70d70b64d7196b330bc8bb9f97f4bc78164297080b519f4ef99311a5919ca23c593ebec9641cf" },
                { "dsb", "e6724e047f7a8ff899a510bafa1f2f075498dbdcf2bfeab2378c20bf58d09f579abb30ee7f23fcb9e6b676f894871e2dc59fdf7a31729c4b150fb3b738d246c4" },
                { "el", "a834f2a6e0225879e6df7810fb60d41ab897898d11d15c31e16d65148a5cec8330c0f1aecb7701ba01c00294a6b57c7c7e3d2f8b6478b01c4aeae6baec39972d" },
                { "en-CA", "848fef61a4ea78a7abc326a5c8fdbb54d1361e6862096ec8c9ff6f1ba33bd23c6189f1fd7d0f194b63a3acab3abd792adf73800b8f2de6018c7baeb362f16c2e" },
                { "en-GB", "0b6dce1920ab2be1480da615c8047c06127e4e5458f64241ce765946bc75c015a122e03a5adb2f0af3dd8361b56de8b67ee818b00fd4ed7a3fb7d3ef973ee875" },
                { "en-US", "67128f1ad4eb93c24f0c0bce211b17cfa60e4d7bb94055ee1c35269a9b64dcf145ada36ec231923dc9c31155e7d1537afa5659036caf782218daf15266d88fc3" },
                { "eo", "e794ca62c2304f884f8ff4fd531c7204b245ee6e6f0fdf07de91f767b1f4723c4ddc9dc36ac1202e557ade1d04e85fa174a2780ded784c2f69a15da5966fa005" },
                { "es-AR", "06cebe4e2b6861e1befbd7ea73df536e264defa87e171e460726983df302079acd0d8d9f21a1419a4b6caa54b47001b7f9de92baa3ff9ea3252a04a6a7f8792b" },
                { "es-CL", "ba1226f46067f43653f9f32c79b1356c038c05ec149f2879dc3bba143a7598f78c6cddde0d33b587e3787d7d63b31bfae21fdc8798dcb2262015ea98102ee2ad" },
                { "es-ES", "6c86ddbef61869015b79a4d6d076ca03fa81ed99c9248405073965a7f3d260cbdfc0da3dbe857d0fd5cf509911c4e1fab49552e6ea400924f00bc9200bcdc689" },
                { "es-MX", "c8de0b7fcdcb507a55ec0068d71cda6a0331f3bf20aefe47f45808bd8966856f7d7413f96758b092f2b4ca34660f78fac3b2617940f6860eb0bcb9e5e9d73ee6" },
                { "et", "bb63669c3cd9969e272aaf35194c0b32c2319f9e5ed03aad85785db7d7bd198db0afe550117801cb0b137db3e0ce64329648a8f7b246631a5464e168918553b5" },
                { "eu", "3fc50d348f1e65053088ed06f6f0e5c96e0c583262fc914f520e82c18b5920026c91ca35b942cf67e1501acf857c76e7e930f40024a650b8ab7071b241d5f572" },
                { "fa", "95c710e981e38ff8550a579a394a64075f286aacbe57ae7df4cc39e7ee93c177cd43bfd5559fa82779d1a86ea2ea97ce0403edec5cd05056f2741cdc430f10c7" },
                { "ff", "c370d5334d9a6961103fbca989cdeab76b888777d4c0a1dacfb39ee8a8521e1f3ef72a2ca247539b073c61956ac142608ba13a18a67eaecf6b3f21a0a74c4e85" },
                { "fi", "369b338da60f1c8f644359be2bbb6c219bdb21e70ffd55e4cf9cae1b005df1e760e6c23866b76ab9bbff8b00cf8d2f5a710173c99b28ad2fbca62754708323fc" },
                { "fr", "9fa63eba814804511069272f07f47abb452da6918de8595029280e87f88f95d4f981945a439b32d6a7887fd03b41a0077277358a81147fafc77647e6554e50f0" },
                { "fur", "84b588b75e64858a80158d587f71efc8bf89d9ffa888fd31cd688e369e9a691d43c362453b5dbe41e0a39f45b94894de48786bbe8858901ec8e74c43d61086f3" },
                { "fy-NL", "f1354229336aeb93516d71f937f5ab774e141467538ae41bbd754c17dff1356fb3565e1130b96611151f227ac6b9b99129bbb468a10d3f98c1688a467b9e122f" },
                { "ga-IE", "3175dae886fefac41ad2c2bad246ff6118b54f0c8720a106d25075f351cf625e5d8783c76ded1447110abbb4c029e74275a10443187366a83a6255e3d1fef56e" },
                { "gd", "398f8d90af85f55cacd6ef7eac17d8fd8be7757a740037cc00bd8bcd73b3e18443d352c5677a2aefb1d24d0c50b2afe8279d1e58d819eed92fcade551786ea3c" },
                { "gl", "23b1cd39e4955011fe3673e04e8ca231d0dcc5bc39da4621415c8ee6d5e60a805d407ac64ba35a905d692c05f2c22273268b38a0170ab23a2bb89a745d645629" },
                { "gn", "ee9e8079fbbfa72a1249aa98381c252a88c55093112083399fb2599d79e0e10a817fa1194b37eea42e2ac7ebad20564429d67944538497736f5acfd46bc0e214" },
                { "gu-IN", "d84bb0eecf1126695cbe6e7849f63b3688a1bfb4643ed319f98b3e4e291512591a6acc818b81c98b0c3a5f98aed9eaad75bd2bd13276a12b1bcbf6137edb2a7e" },
                { "he", "dc913cbce02802d1eaebd5a11a1a4a9b454d23d166b42817f4d48e3337566b1ba8d560a5fd65dfa7c2e11bce2efd0d3023d68b25ed37bfe1c459ae6e29801d72" },
                { "hi-IN", "e83e6b8dad4b1a265a0ad9ad8dc28428680e8f880881e5ad962f345ab1145c5c65e57745f1329c0ac54d501fb807a5f2054393a6c9b04507ad39325a00a10c98" },
                { "hr", "03a1380d9034d2a9c3e6346b67c853d7df0a51e4f3f39f3d13a96630e12bf83e8f2e9c4b876dbaa149f927fdf084d3c9c84a07b7a70944d72b20eed9176586c2" },
                { "hsb", "6dbde921bc9bdd80b1e9b6a39f5a6b8db5a5f952ce8ab8223f3490c0e3c5e90dcac8d9169a3785fb8788402e5dc38dddefa8ab3251a94067776de6913b347522" },
                { "hu", "34cda20350af5b0f3ec8fb2a2dcc1772ec1a720fa39eeb29a022c68d65005e15252af6b5318bca18ab51c309a4a26618bcaee046127f5cd04daf1c84fccc2c1f" },
                { "hy-AM", "f7c8a65312a947f1930ab82567d56b51e3fe80b5f686d221d58e5da427c82c11fd83c40064a7d344963bcbfab91f0596f5e274383a8173e5b3793117dcc3c3af" },
                { "ia", "37a74d1063132e04c4810bc85402210d1e590b677116ab87a382643edaa70f32cecaaa0c13f368620c3f0010c04fc39178fbc56de32e898f109ceb7a5d32df36" },
                { "id", "1e9e90e191b545474b695cfdddb625abc6ac7d07d9a02c6d39a8bf2c16a5dc2dba127f2bbe9f7ccc709b34edaed10b875b5054ca32ea46154afe68bb5155caed" },
                { "is", "5d97b4bc622fd098a1fe97664fee854336681c757ebb6d6469268bea11be75170a7fb3b7dfa7984873336ddf6e1773404cc071faa72930eeecb9c3adf52a1c69" },
                { "it", "ad7c36ac16383cf9715f39c8321836dc37db050bfd90b70d77cf30dd13b5e32cb2fefcdec697148aca76864c28fe273cd468839a89cf45b2b0054aa09aa1bddd" },
                { "ja", "0362760b2cf26cbba44e15f5777b4fc18b04ff9abd8ccce746f99034c7b50fede00e81469ce2d3ae4a843f71fdea26b5df13268943520d5c1a3022ffdd270f9e" },
                { "ka", "2f95414745ca01751b422452ce8ac7241aff70df0d9992541695fbcc710a1e88aca59ff63ade046c07643fd643928e81721647ef6c1020910548a86b6e29014a" },
                { "kab", "b3e6e9038c1441191690c94165cbc654a30d36086066363591f61b0b4dc7e97c40ca7f84025093ca25b0174e873a6bfa695b63d1e603ad2b535c92381fe3bf35" },
                { "kk", "bde338792f2332a28925e28747fb4054eb5eb1edf19df51b792a9d950972bd57dbaf6d0d78eea142e2662f70a2f8f64158b468b3eb4ca93e5f691ba47595e72c" },
                { "km", "9a2bfc57920e4a42e9d0c4858c32e3e37675543826baaba34abf24f6847356bb2f7a394028c6d6072946f10f52459ef00f3132a98459f96b962f66aedb88d5b1" },
                { "kn", "c20f6a687406847fd424dd15ccec30f0edd8afc69f82b9e8197e1521ee56bcd4fd9cf84d142e3919f7abb7e540035b64c0a076eb231cc6e631368ddd7e0c9c0b" },
                { "ko", "ba7d028373836ff0515619df5c7b544efd6c20515a31bd7a77490f9ffe2906206e1132bef64d517b9e8d8d78c4d1af6e83a30b167ab95f5944cae1b456821309" },
                { "lij", "996c49dc90eb1a376a95c24d438ad25b84c8fb1d0d99209d49b7d331f0db8fce28e8f9027a8dcd8cac775ee43915c18d5d8c4a6aa92ad5ebad6124f0ae70fcda" },
                { "lt", "f27be866be0b66b02dcd1b4731597755ce1b1684fc762f4ea95b733da069cffc010fafc3bac2258432a1aad56874a0acafa8a37400ffa0078b2fd1381558a770" },
                { "lv", "2ea43fce7dadbf36aa37f788e642a04f51cff627f8797c35158cf79cb7113c8e8404509c7968b1123ac13d080a80959b6c64c954e0edaf75cc1fac62927547ad" },
                { "mk", "ba761ca202609b873df272db4a9c91c80b544f69b552b54b174fd47adb21bd76d6b802c50339f535120728f7c12698366abf9572c7f0e9122da33cec8c69c7c0" },
                { "mr", "a8e30c68e6daa5331ec74fbfdfeb302f1a6df348a207b8655de906c545a87b8754d44e7ed7586fc2d680aceba6b33a3a8b79209d090b9b9d0558139b1fb39847" },
                { "ms", "b23e5d642f3cd7bb123633ac80cd9fe834792316627720940b8ccc2caa20ab62b909dce4053490f3ea8a9c9e66d5791b345b1722c7f2059e7dd56d64080f3141" },
                { "my", "f7871b9d9e0fb582d0818144ff830f4a8f96d24396b56f4012479b585a515161fe4efb70e8e81d8093df4390d5cea71e064bd150a29814a30fe311c10bc175dd" },
                { "nb-NO", "334edc81d4e052d49ceadd205bd38d0f9276d6858358f6cb2ce838416c0fe0e7ed1be6c0d0cbe847b09420746184127183db86f22241dcd869029a0516c3cd05" },
                { "ne-NP", "fcbeb48c6c232453f287392af9bccafc2b53f220c846f18ced6212aa7d04840447c610bcca170ee2f29a036443360a95a27b7ec6cf4164a255bfe33415121450" },
                { "nl", "2f7f8380972869351497326907d2527219bf2516e772fa99e9cee8ec9ff3b3b49dea974af0433d29bf6f20baadff8df4771901c065fec9811fbc57bbe2516bc8" },
                { "nn-NO", "da6f102c4ff68e3799e4baecdb4a78563d8bf7178aa9eb8a8b005e8049ca3a046bc77b5be3dd38b0fc3d4954c9af0d472e71b825ed01236399217a38d53f203d" },
                { "oc", "a68810e8446e79fe13d38816a854c13e4b63d8fe1cadeb4cf440fcfaef3f6786b21656d7c1108ec2ca6a5d1479c72c4c83e8c9aaa665ecaa5ad44ef31d5b1b8d" },
                { "pa-IN", "e6f0856019a57f59711e02a9c6080ad35ea690d5c45d3d342daeedbd9da368d695c1d5d8de6bfdafe0f99b022acd702381ba96f8463865129017e6b57278045f" },
                { "pl", "36f55126447e5129d505c13f11f79b7f071d4812a90b288ec18667573ec0f4f9cd56b9bc19905c2f9c7389e78b4d554241248dc8326baa347e6b51d70bdc7593" },
                { "pt-BR", "8f21babcbfc0f962b2a8878d90102323642735374faf4d7cae18e47aefeca00d4cbad36e4450df47da9d03027aeea679a95f8b3e6010f218be8403a5b438b986" },
                { "pt-PT", "9d9d67f8520393253f270e77831866b61c32914bf7ebb4d113102a77e6d32e8235f6ce01c6f1a93d7964d1e5f3c81949c4b1052d04bd8a855cb0bcdf7f62f549" },
                { "rm", "94d4f1ff83930904bbc5d6ef6dc4de6833adf3527f1bd1091125f286437c42a7649fbb2e2badf15f70eefb0248932891e178f705b8ec70bd1dada93f763b4e72" },
                { "ro", "caaff4f5993e8cfc642d6b01c0900ad18d960144164d0ee693c1cd71da0adcfe83d1ad55d33ba1a3d2d29ea1575f0324a1dc19393dce266f10f901b77f1d9930" },
                { "ru", "9f4682a9737d12748c89bd843e4154b75c48f9d4f167c25f28590bd59d269b922193493645534cfab53840af339b72a82d8e7eec0b292c29b2bee0f0a16caa00" },
                { "sat", "d93e8996a3da1302973f32d5c169b5b3237d0811603f48881a69d3e373e932e44db922298554ab9700dbde0c3f174da503bfbf42d295571f84a9deada4e90e24" },
                { "sc", "8cfdd948a810e81b522809997947daae624a520c0e8a59aca22ef5e1723f806e8288440b929f18152faff2892232634103f183ba35e8eef754df98ed2cc6c81d" },
                { "sco", "c5e63918577780f1318a05e602f80cad782ed53beb4ef0aa270dfbef50a95c3b52adb75c8220cd89305b6e686763d472d0755fe62fe30d8610f7ebb10bc2317a" },
                { "si", "31d6d99854b65ece70f489edc4d1ef95014fa8c4b23ba7cb99f67dd170904e9ad2eb5776b9b3fe14bf492dc3119de2d58ebce64d2fff1f4d3336ce99846710e8" },
                { "sk", "18430776e747713c6369f3d17da4083fbdd0b1dcda28b2012b1b3ff28e4ab6f2c29a9da49ac67c6c18adabd64be3ebfe294f04331a7dd744ab2627bc0a391f1b" },
                { "skr", "803ee3c897080767f287f297f5ebb72648e4f6bb3c7da5becb9fba6ddb0b82dbd6409e9002579e935197546ffb9acee0f44ec93009907f96e1b31594c08fdfa1" },
                { "sl", "7c111bcd6ce56e8f33dc8b48165f1080343fc542ff5c4a4ab5f769410a44c9f667058589ea2c81cf8ac9bdd9891c318e7d052d00daf7e1fd449977f7ce5c8d0b" },
                { "son", "e4c7270c89b5e44dd6f6c90f04f01a7870f4d1a671dfb64fde9d6f56a0d1afe8e383476666fd5d1677a3aaebf30454c2f1eb364ebda0ff5684b46d631955ef9d" },
                { "sq", "97f777a8c2b130beab5d969d62eeac2bcce4a8fea2f56df68dfbc69e49bb60709fe0d103e56df8affb39f936916416c3a0c43957643c1aac0bc1d91d1952f6c8" },
                { "sr", "2f5c38747bb37102914247c2902ec2822d58941f4c6c35a54df3b02b9c2949417cc1b29e24dd19ad691eb16c00f733be7e005e9bfe4596c6b98345a578bbcc39" },
                { "sv-SE", "d53439aafe6a5349ee38d49d794334947333f45a11e6f8e5d34f34932b59de3dfcf36daf63a3d95ef651dd6b3f4c4cdbb885f5657fb0166cdefcec1078790f97" },
                { "szl", "2b7bb7b6c65d875ce890f8ea6cc848ae4ae3c290723ea2dff383dbd6d3554255396cdfc205981df711066d640c742fa8c1d6d1026ed3d39a0479b93c23079486" },
                { "ta", "b6770bcf6fea62508df751721a7eecc8975abdc66d791fefcd95ffbc1e823ab265834ca16c3da748b68a724bb629f11885d944e06db880e7edf2a0ed48f0b759" },
                { "te", "69555cadf5756f2bbe82ed1299e4160d73cbf1d62c16607b1a43a3eec592fa220abead400092e7e80661c20f940919517ab41a1adaec5944a64896ec7fae1474" },
                { "tg", "7d4cced77921acf07bcc86cfa92bc82f7104cb3010f9b8e73be9ffe4c2b84cfd7ef65414317efc3216bdaa9631b6a69ce4d69e544bd26a1b3cd0564c372a1af9" },
                { "th", "93c0ed7fcf21f9846aa7f27e5ad48742a5a4f3a6e7b011ba0194df42b46fab63bf9c888ff1128bd233664e1b792c3446d73db338e17f5debd6743d42850ef615" },
                { "tl", "d10f9f344f4287209dbc1251749d6f6502878f7d11e20fd133be94417db67863cc20fb68b3e86ddace9357f9bfc471d53d182aa85c1c84c1c1fcfc3e63e49a7d" },
                { "tr", "203eef5e5a71797b9ce9e61da8fc5886ff25fd5062aa4276e0d218cc6c09693dc72ebdac91196dfb53b572044ec1b21489754a4c15b501354cceeb7c332c283a" },
                { "trs", "67cd78e59d351ca94cfba042758a3ef4cc815ec295e7240d07dcd3eb9cf54a0791f6cae1f9a00774596e1f869c2597a68e621742a1f9c20529c304fb2fc9a8ca" },
                { "uk", "6069ce49cf22d84788564f7fb869dfd2fa34e160bdb9d2c8aa15d7814329c020af39064f596cbcd7d304c90a02b4e0c960e3413bff7bd18259483b3c3335f3c6" },
                { "ur", "9a5014ec4bc0144181ca1f4fc7b60329c5382105e50538a9ee8630f8531b7263ad06b39f24ca699779af36730f60ad396f70c0d226c45db365fec37e4e7f72d6" },
                { "uz", "c2cd0f2243a7feb8a698a2a65fab7fb9044e8cad6e54f04554d80196b66d714bdb0f20029e951890048a8ebb197c3c9eddd38dcc5a84b4ae6b113a1e1dd3f8fe" },
                { "vi", "c23b24e9277037c385c5ae42bf6cca03aded974309a6cf29d89584b62ce8f6516b6164352bef9980f0ff0892e6836d3f724adf3b9ffecd46c6e76a7274e95afe" },
                { "xh", "37f7307da9c58cb3f546671ba6f7a10b4382ee0036333ae8190b1cb348ce8ad0014a54fbafd15a7b139447c9ebf892ae53371c69111c69fb68ee6b882e55be24" },
                { "zh-CN", "b3d3c6074943b7a5ae143722da3939ef362c88346b3766f5acddf4858b7ff8c5729691c227277016317ace03de395ae4cb2783168829fbfae6383740e9d0c1c7" },
                { "zh-TW", "c5553e134f3c4897eab6a87d4946dc081da7fa048fd89386642085ba2ff1e74da498cd2858824b2d86f8cf73fd11df15c045d93bc515cc2196c7dbb9a5f723b8" }
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
            return ["firefox-esr", "firefox-esr-" + languageCode.ToLower()];
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
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            return [];
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
