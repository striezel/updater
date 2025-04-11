/*
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
        private const string currentVersion = "138.0b6";


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
            // https://ftp.mozilla.org/pub/devedition/releases/138.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a5eb3970eb77781091ef8afaa3621ccdc2fddefe3b9358761855c392620a0f4481ab79a93b607100077a25248c52c2b1febb10a3356b8228d122326608d8d407" },
                { "af", "a0ed1a6f29ae0500983ad31257e9bba750c593cface12d4ad533d02ab95c6233be527c86a8c21401d77c448c7f3a1e687f03b08a0850db2323906d53eefe2663" },
                { "an", "278f40352e706ec5291ce25beee10eb2e6332f85914b6582ced065b06a2adc9f58f0dc3f72a08571e142348ecc195e628115be6efa8590b18a2b8bcb81e283f5" },
                { "ar", "b4dc3a135e2f44bbc314cb2afb18f85066515afef69e274b772cb45c0248ea35042f24cc7a52814f97f30995ffcba01370a6f827d202e262b69013c0ed678ad5" },
                { "ast", "a238319a408d4920750615ebd5e54907f1659a8af4e95498e51571d51d245dc97b1724ad3c8818ee286fd32172dc40d54a7ee2c7368d54fe9d0869afd011663f" },
                { "az", "32de4cf69350b5d70754118c98477c62f81e4f96ee9f7692a6a5b7dcdd0e8a3f7f549cdaaa69d0821096e7df31f95748cfb3815a9fd5be6d0b57d7d0cd081eec" },
                { "be", "cd9795239c06308b386214314680f61abf7fa622e30a00ea844868cb38c9077c896b5dd655f1653f6251446248fe792ab3546ff714f86359ae511ca899f206a9" },
                { "bg", "5b8b073b32a3e9cc14151d5e7e12ed7dbbeb7913b1166ac57bbb9fd179926ef7f10a08d2145b2f5d477c4c0e49b239cae1094efa9c2334fbdf27d42d25b72526" },
                { "bn", "4e538ed47f04353dd36464a8565c13c3700395bca74192393376e2470850f0a5fbb7ceb710bf23904e5b95d9aa803554110bd070c2bcae2ea197bfb0fdeb3c29" },
                { "br", "93e8aabaece6bdaa7860cd5ec822a06ca9727331b6b06efb17ea0d9c2c9be75d12251975cf75b7d17f569cd5dad1977d229e8a19733338318773c372b7207c1a" },
                { "bs", "c274a104bac6dc6a7383b5eaad5322890081bba39d37224e1a4dd077e37568185f03adb48a66272162e9cbe3ad654f5c7c54e3a05da1bdec5652dcdf16e6d127" },
                { "ca", "c86267ecfa46f1c32f164623aefdb59b84c6c3c4466d1ed5e4bab3a5e8748ac59e345f52df8a2c502aafb9c97b69815eef6e2e3aa53dd393d4d39c93b753d1ce" },
                { "cak", "c1d215c386257efd0938e6868dd40be9e885d6b95194e3d6e1b77ccd4045c4bcf347b6820011b9b0694278e87b27795ac9b4dcfa286407993d635536dcdbb29a" },
                { "cs", "17db75dfe8440e8d84ec5ad5504a0ed7e46225e50f66fafa9f62e096688a8a6588882e142fdaa8bf1bbda53915e681665e42a247c853fcb501dff203551a0bcb" },
                { "cy", "5930d65881101fe1217dcc58e397c668ad3c476849634d0da7bb9f72030ba64f19e0e1cdd1a2c4f0469b6bb0be66e160640627f0a2be5e4f9e222facc43466e3" },
                { "da", "282392cbde5b9ad7dfd2ef73ae8c5e4472480e13424310589191d6384c4f552afb125b7d4593fcfb7b359404fda2f188413ec72e7eaa22870aa2cc9434a3bfbd" },
                { "de", "ea3c27b7a37d42c4d7a829d2014bd01807e17f028ce4d132100ee54f7940475e100eef15179a44be057c646cdc8266b6f366c70f344563dd9eb657a5010cbec7" },
                { "dsb", "fb0f871ca3c276d9dc73da0988da27ecbc08953e9cea048b7b389cf6d223b528e0a4885126f271d0c3bd86a3dc0af8d44c44a22cc396c19d77b7e5365bcb0d83" },
                { "el", "a962001e26d9d3fe12e5edc4fe5f879d9bd3dfd74783e15647d412a076e337cf06dc48aa165baf0c60c7cd26a5340db056de2e2b6689fbfa45866f0e4d39333e" },
                { "en-CA", "2b0d28282878f001314f90551c669ef767006f5bfc5558869bc521ec05f7a35682506d029b3cf3022839cd723306e50a4470b04f7e3183bdaf9f518eecf4b323" },
                { "en-GB", "7185553e1c8fe88ceb922742fa41e5a850e99e9e095906ef72e568da08992050574721728ffc7d4fbcdff0a59a0e7234fadcb507010d9ed8c5b53efe72986603" },
                { "en-US", "d14271f8c0ed4b28937c7538f712e784fd239977aab464d2b6f5f3886eb53db3a5909ca2e5298a1079050a80aadc60b851827c2b85ba16b89c20111ac71a66e2" },
                { "eo", "eee06ff75e1657d1de626a8334d8a9f60245df754f7a42aec7b6566ca907a1bb19f59f23fdc43b160852aad0e8a8df198199ddce4fe85092e1c431efc09216b5" },
                { "es-AR", "a3d4234e4fee8772abaab47db772e60cd0d9c9f02e458b913c5188a782daf8225b68a5b6f60958704522a50aee5ce9ccd82e81ef37602fa394b8edefc6ae41fb" },
                { "es-CL", "0ff07a7d6c34983ea4dda6ea46725a632bcc98d795e8bbf27fd2842b6a11db4c3d5688d17ea8c2f0ff74848bbc664a2396e660d5a00948a6bcc4a4a47480dc76" },
                { "es-ES", "1598679f6adb3ac178d23683ca2f021f9400ea553b14ae9295921531e0144a3228bee63748b0becc65481659daf64b555aec606251bd421de6aaa3752ba26b59" },
                { "es-MX", "19c4f893e0615896ec4c1bbb523dd66995474ecaea5e7255e4091e7760c0cad2999d79abb6eb64128cfcfe1ad6df4e37c7ccd85e87f7108bd74c34f38315fde6" },
                { "et", "a673d09f27079ea3df60ce166d2b9cc034e6e1f8baa454b0f49cb3e28f4d7d0435c4a5f8908420e25e4eb57a3fa408cad45845454b807e8f213960fbdc54f9bf" },
                { "eu", "98527e3ac9203b49300a0d4a9f82f267b5c6ff6ff71428f7a952e70c819105c3108113eb5f450ce771295849c28ea25269ba9bbf659ef9ae03c52a2a7e789860" },
                { "fa", "29b8294880d3187438dc6c52fb537fe0558c4e824c293a6967032e70850ddc62f3f745f9fcbd16d61b2b0437142b67a7fc4ffb5c8f2ee273d8fdeacdbb506d12" },
                { "ff", "0da5bc3cb31a05c180229f4ea2044de7eaa46db1f534f849d96818eacea8af7c7a979b973935022d9fd36a9e4c3c9d37bd13ec2502dde45652513d63ec9da508" },
                { "fi", "e11ee0ddba596c719c19b1a7592646051a70ebd054fb7f3400da529076f07091a7db67766ad6a991226fb283d9c18dc571884ab2928ff66d70cb3640fcd8b5c1" },
                { "fr", "74b988d318752e6532caff161f499973720b8201869f4dc6e78a8c93daa07ac3f80f98abe3e63c41ada5f7036fb18c0d23397216148a36f534b635dff9262c4f" },
                { "fur", "579964b5fd5e22f2c4fe41013491fc81bbe500cc1f6426c2a40a43d7d5b8aa170dda5095cd2ceba3e5d05643b714ac53115e7a5de308efc413b5f00767588a37" },
                { "fy-NL", "6e2d10158c1f1a0337d8250fd032afe522325c0a51322b0b6c3edd9382cf4c1a086e433b6403cd41644b0824defe6c0b4d924efc0411f7eb4f15e1633c9b3dc4" },
                { "ga-IE", "598509eb3cc1ddd295e9464a44dadab2477cf18d5031268b5914b728499f2c67a32493c97db614356caa07ef0c30a6fb8e6e6f0c383246b2dadd7eaae5a8a369" },
                { "gd", "9316e038861aa602ce8b00822dbe55bda0bf9499f51c4bb23dda7e39a7c893bd0517eec3e1333cebe8dca20f3a5c053e07ecc6c708e6dc4a957235e3c023ece5" },
                { "gl", "8cb2abd847542fbd032768ac0505bfad9f1d5992a35541198a79c46b1b01861a7743aca12d21a92ce11f0fc9680ed7241864eb827802fa9bee7f66554e66d7da" },
                { "gn", "80289ec743f882a1258e4fb0ddc15b473aea66336bd24b7aa6db4866c7ba2c8dbb26952d30693efc0ce2581da1c1e08172553d5ba0bd4ce4cf1af62205bfd5f5" },
                { "gu-IN", "e35e30d32bf99168f1e7b23235f962df7533f6ed9585ae1285d68fac6215aa56ab952178309338656859db0c59473d56acf24504ca57bbd1ce47293d94a2b58b" },
                { "he", "a783be4e1aa93ac2b7e92a0223c018a2f408c318917da0130b9d07d629e2791906f138fd49976cd8734f0ab8ff57568e4d8db8a9944874e8d55521196efb7675" },
                { "hi-IN", "37212631c160296abdd7b8b50d2c8c40939ddfcb630c1fc272b135620a663f183809dac8352bf25b76430acb1d3c48d200ba12b8de7dc46e951eda0216f81af1" },
                { "hr", "76e846f3b43e7e218ab4abfca64ed7003566cbd18c45edbba727fdc3248f480b4799c1a133bd9f87414e38c0d8e2fd00629da702f396beeb5f1669cfa01a9ce5" },
                { "hsb", "f94fde359b670b719293500a1530f007180386000e615a600faa106b465ba813f54e9dd94e6d7315b9a1c1acdd3d6c73fd3d48f53c5f4f8c3c102f970923ae0d" },
                { "hu", "8a97bb99ff7fc49e674127fabf8102f4bb845901b4d1d07360777fa088b389e181df45c698350fbc106ef95d603613e37030c10d9a644d84e341e1442176b42e" },
                { "hy-AM", "e4908073e99a4044ae2eadc2676f0f5b51f68ec048574d78aa13690205bd590eace4297bb33cacbe09561fe42307a36e7c65ff7e646daf7b55dd0c81442b9d01" },
                { "ia", "0f5d87038b31608f1e4b39912716aace24feb9abe63d89057d6410a77756fd8e12f98175fc10e5caec29993278e8dbbc4e85c85a9924868e7e3e4ad052c81b9f" },
                { "id", "afa0db81585e0a8a55e3fac29731adef4cf7aa67b0f5efd5e577ca78c192136a98e4d4a1a50d9047064845abab6991fc62abbf92a21ef4432a6c7f4e202cfd7e" },
                { "is", "f4e756b2129425c202468f78a4d485588a66906b336440e4a6d894c84e0b995bcef96e626e0eaa919e7c46e8d9596834f0c436cf5a7d26c3d6439085040e0cd4" },
                { "it", "4edda25495dc29f07c326b4ddf4c4314898afa3cd3c82437dc0bc099615f2226bdc43ebeec2e0736663c55447935aae8f78d9d2f5a7d0a49bc354bb9a3cb722c" },
                { "ja", "77b02a70d324e043935481542f12188d16fdf928415b71531a9871b71941236324f59064e62434f3266617108d3e59bbba8ed581878025fbca87c089ee179e32" },
                { "ka", "56aed1156db65aa13605769b50a4bcdc9a918571c6d3136e939bb7a2448f6b75178d27d83a8fd0f9b4ad9857de1b21134f9190352d4eb5cde93f2391844cfae6" },
                { "kab", "c7bf791f8429e2cb11ca5cf375ee98f92b8dab4d01c5d299f921995fee6bd7362f4e424c1806e3926a4001e97144a47e036286d86c51b9f1668a6db1679506fc" },
                { "kk", "62e283c92e170c5f9078fadf4fc9219c518351a0ca1c9a9189b0cb793ce8af05bd7d4a6bd29f8e63e5ae6999d1dd2ea575384823e59db3245a21799b02f0c59f" },
                { "km", "f45549090dc20516bcaeabe716ac108b7e8720f5c165d541df3bb2bc27fa44e3952eb5549d75f311cb91eb230e5e2a816ccaa4076bc13894114aceb38c7ab2ed" },
                { "kn", "f72b6e2e883aabdf2b0d7982562d7daf88956aa6728680c3d2e200cef77ae85619bab803e73661388759caadcbdcaef65163a1e1846745f367fb2203efaa176a" },
                { "ko", "ab7b50918e42d2145db033cf990943b85fa25f4b363ac555f34a3a4224948e4f3cf090d57c80377b874edf35baaf364d6442bed1fc0dc5e89f698e0b4e2dca93" },
                { "lij", "86e7e4a889fca56550eed2755b96fe93eefebefcf471595e5bc880d765d0c4cf9ff08060507931bb13287cbfc41b43676ccc932a1bad8714b5f7af99fdf59443" },
                { "lt", "58bb98f6a1fd9daaa60aa585787c4d2a09d49831558d6255da4b49e1a6beb335f028c9dfb0c996b58a1b7611cbb4f6d6dec4058296ce3377ad86635bdc1cb9e9" },
                { "lv", "ebaa08caecae29e120215fa4c3914a1a7b65bd62f0bf14ed7fd7a3dc91bb293a20fcc47335e1917591a22f54a0d3baa43784ea0843f54167d647d9fe0d52260d" },
                { "mk", "8eebfe9e658eb20813c26bb2c879fc68b96218031d8f94d355e0d47e427b12371651d112991dfc4979132cbbb523b37e997b50fab21c83a5400d354419f08b6f" },
                { "mr", "1d07d03468319fcfe6cba0963c627af29cae6bc01cdfb30a559df116cd6f3e96750cc65c13d716a5238c2716331cf396234a0999f379b1dcc5012308efca9bb3" },
                { "ms", "1b3fba26b49a27f6804fdcd9d7de9cb78392adc164ba517b1a2fd375ed52c3a7d9ef41408317178536b0bf7c4060bb8992f0513a3e6f19b9e4d349738032476e" },
                { "my", "2e283796c185204e76c98d037233ba646836add056633274fbd21cc7214179362b3795dc125fdb26b3c220cd9def847dde7d114c2f5dcd7a8d172d689e07e3ff" },
                { "nb-NO", "ee98f51f5a0a7caab51ffa5501706cdc556a435842f15b55c0caea41bed63dd5574aa1d2588fa0be4a60d83b79db6d8c40186f56abdf731d4d81d89fbb017668" },
                { "ne-NP", "8a4df567aa807c3842afe03c9654099c241a5ba801e72b823ac8db35a96cb75026eb9892abec6cac05a672bef4935e8b5d416b3614d27b4eeadac4ae4200c0b1" },
                { "nl", "1efd91eb381d41b1e5f7a4037b930ffdfc91d6e827a237236ce1818fcffabd1385f9dff5ec29fda5165801e56273ae9c13c70fa23b543e060559eb9a5db71a4d" },
                { "nn-NO", "8b45958d736dfb961faae0dadcfb87d9d4632f72fc06adf8f0d6f8a4c8105d38c571bb362fba129cedd4a7c16fd3cd2d98329b2caafa90a7b1aaed5d3c87122e" },
                { "oc", "9ddadaadf96bf698637606c54788d5a121abae5bc4421149d8aa73f7aa2014255b7cfc904939448374710d10585e3ade6f17e64c7435dbc0f0f0fe02eb057178" },
                { "pa-IN", "5ea711b4799e045f7174ee412de3adbccfdf03c0d6711b28f27348bb769fa6e5e32446cbf8cb23e0cb75385b41962b6975f7dfb1cbc8057434f809e23222f93a" },
                { "pl", "00d929fbe0babb0a49fbf077fa883cdb5629a4a2c1bb5a6459d7548816ef19fbc98d0e62ef8b719c89530a0213f53e118cf93a6b4a015db603d1efbb901ceacf" },
                { "pt-BR", "0106fd557332358618e4bc8c33b2e771466228085a545f1854f5b8a45d2985753b1cc128cf70cf1a6b31516df0bf14a91ce6cda34df67a2e2ee13351df2d6d15" },
                { "pt-PT", "f05afae0c39e718eda05dab1de38d77fd16ee3254744d4343fc807275236db4cb2d60572597c18c28f97458d5254b7334278ef51054610a662619b0fc0fff6ce" },
                { "rm", "3bf41f52d69fdbc821d46591e1f7ecf0e6405ea300d0cb96ec6d8eef8aa4e7ac7a92a1908e25a70d4d2e6578082796205fefa9a5b50ec6a70ea263f127619933" },
                { "ro", "3778c172039e59b7d282c4003cb93a770874ead33511aa23829d08126a925a10950a52140709d9b64a63f35a8cff34d65c600e93c7fb87517f3b7d40f387366e" },
                { "ru", "feaab4cac4137fc1e0df221d7e8df3cc90d38e178fd8ae0c2a83468a83be5b86972356f7f3c04e58dff97fc80eeacd82d13187a6eb37f48ab7e71d91bc6843ef" },
                { "sat", "3c2a82171353be5467e6044fa52a782e80c7f24bb44a97f4c1d224ec3b11c5a9b023eec15ee693d27d445982f5092b878341adcb4b308eef080603250492edef" },
                { "sc", "3602143c39040dfef8230ca04f6e45269c7597280b1cfd0af3bc03ef023b0a1de7fa466971401bf5fde570f5939f47568c12d97480bb4ec9295df5aa38f11db0" },
                { "sco", "86bbeffd1dfe2bea5520b3780834eea37e7151ce8b20ffe85289805af684c540f5c28aa2d4b76f4e220947be525d68d306fe06b0c158e4573e289c6596ad1d95" },
                { "si", "d643690fde04c8623e71fc9984b14f9c1701e4be764abcfd910cbc35e554feffd7981b2a707421c57dcfb373a9ad5749aaf5d57b869e977c945f0e8edd6a11e7" },
                { "sk", "9328e90f39c25afc3047d545daad90af2fb50c59149de0d521567d145bdde7bc6af001cea7b8f4af6d9018e98c1db22d96f842ca4bf3192a1bbcde871791eacc" },
                { "skr", "8f859927895e2d9b7e5391e57818a02f7c57713e1a7102b5588655dc8a0ab6a9378608487c6e75af5a64119db387df301d0d0bd9ea42350d5af89248f248a082" },
                { "sl", "ad8bd9ba3abdc9781de5faceca2455c6c2504a02ca4bd9b942261c0fa72f687ae61cb7028cd91e7b4214a0254ad232cc87735ee9e576a86e462ca57410e745f4" },
                { "son", "211f9381aea0a501db01cb8d6f02c1f8169606d5bedf5ef19f4392030489b3badce821da914bc4014edf5a5febe10c5e71ea04dfdf9a73f151a88cf85f8460ea" },
                { "sq", "298fef3b50b8affdbdacd398b068db92229d001aa744fcb2fd798c9f7cead79d32fe68b060963bfd851fdaa61604828b0e841b10cd286c6cdcfab9f5acd3fb92" },
                { "sr", "f39d93c02d18160f90859c544c1f733848d2c0e5c941a6a72daeea98dce4664b76cb9d3937f1319e0575e3ec3af6eae402ed3b0c7d4fa116c88407386c811cd7" },
                { "sv-SE", "eaa5455ca3066858d5247f01f4c837aa2f7cd2f63aa408040d6e306b2266b35e8d03cf4a3197cd366b35dfbb1916d503de42ea56fdc37be61f4dcda3cb9ce02c" },
                { "szl", "9492300f019c966a25e83fd8808a3244845ed0f1cd3e09fe2a2ca6a7aaf681a90361debab4d03f88bd00eb036c1b33a5899bd6a04aa7b5c9fce89e7a12199c2b" },
                { "ta", "af70ec0a6d69729c4023d3a2960654a8dc09f24b98d3324fd0dba679b1818f9579bfef26b8eb6e236b8b54e5cbfe00f9e8c79a933680b59de7e47fb01c4fca03" },
                { "te", "85daa425323def68844a9a62c7a8d755134764c4c7389d2ed903d3b825d47a8e068e04b0e313f0534cbfc0255fc874191ac1b931e2eda1e9661c4b8b772aa4ed" },
                { "tg", "0702b6158ae078f804e299c17734502577ce0ae71fd95385a38bb43a21a011c749a846e54c57a5e5fcd6ac538011b58cad5925c30fb68b25c559799057e4412e" },
                { "th", "a4b40ae75ab32c65c60f3a911c9370c81aa258621b16f89107a33a1a3e9cbc26cadce1db70211ca631b3ac34cda00c9576c03b1199735a0bce37cb065688f711" },
                { "tl", "df00336ce07511b7e1eed9a35a94bc8024ab6da2bd07f7695df27551eb3122954a2b08d47452c18e613da42869e44ca95075aaba1160e85610fb38448619003c" },
                { "tr", "8e5edfc46559d8f369cf2e73e1490569eeabcd4139255c6811fbbad44a590c6c6836daf340f9a503e9d77080989f950b464760fde9acff93796af0de52f27934" },
                { "trs", "4f468b94982d1474c28e20e5974fbc26e72a0c7de27f213170314a1c5ef927255c18beb831173e171a7d9c842290024debb3f9eae5fc1e962adf1dbee9ab66b0" },
                { "uk", "884625b199fe5845207454e145fa5e219fa606324b986f20399c869932ab8047804e2c151853e6586a29ab1922e74c94f6afaaec29859f82e8774529e5a4c4c6" },
                { "ur", "29530e9d7e35bec15474e974b685f93b8a7cc76404ee44e4ec791b8111e2c90a4ae29422a648359a7a0c09d61d835aed2035e196c3059fb760e28c2a0f40c798" },
                { "uz", "7312d5fbc1ea76be9f519018c328d73b2a44dbfe27640f1c66d689652fd917e24777b341374d8dd57d3aeec6a5c07b09fe091de3cee45f07646a809a110d35f9" },
                { "vi", "2135fe947d06196181a0d66eb0a2f05ba685341ca4d1d6602f7710c31c482baed3a937493e3d4d0cfe1fe92af6a00fc892a0f8582903c091eb1ddb826f184e02" },
                { "xh", "d40b297fbf9c3b2722f6a449958decea1726c2cdf152d0623301715e4b77000a0e3f96afd99f992c50bdc6499822981870e8281a31264aadd373cec341eb1328" },
                { "zh-CN", "ec1b102caa62795c3fc4da3a3fb55f169f7d6b56fd53e94a89a7311135b80026c4e55165b609c3a4738b534252ba142e547632625ac1a57ff851f2270732e60f" },
                { "zh-TW", "68ada7c81d1adab2f5fd85c5f1fe435db4e3def57ebe466ae6747bce81636808afdf43f9db8c13853169c71d91bbea529152618c73aa9ae276bc5097a78e02e1" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/138.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "b6876cd7e5e4d09bec86b0e78838f4511dc357ad69027e33c06b7e72316c66713e8be0e3eef6966dcae0bbdbfdc6effa92985c2c3da98a6c3f1ee85eecd1b8b3" },
                { "af", "5e2140958ff8ef16b101e1af2e6bd1afeb4e3d6ae08e8421a6cbbcecb596e5c735d98e3e3ed5f346dfb9894b5bd8be7f571914e4d8ec948f22673a3db7c4993b" },
                { "an", "7433c29fbbfee70927312e3eb8d3d5d6fb36fdfd1aadda528cdd5624813aa834ed83592f4055e496f1c4c8082f5f2222133b9b529249738f364acc9484237e32" },
                { "ar", "78077fbd90b5f17928635a7180950ba4e8425c935962854fab164b0b021986332a9a31d49e4c78b76b02a22e419e9b4577cff99b034f212b71e059f08d005f50" },
                { "ast", "b40de3edefee7a95802ccd3eedd16cff581394c7ec8480153cd4dc8247a18964d2dfd3907c7b279f72cd47e9351540a7ae1a2e2587fae67778bff9cbcb2f7d12" },
                { "az", "f20d506bf00f09f2883a5225f4d5a480f3db394d49d95f80d3d63df5837bdccb1c7dd5e81a3371073b60d3e8babe5909a03b0da4dd838f55becda9c25d7a075c" },
                { "be", "37c52137bfe330b19ecc8bc37ec324d1bda0428bb9eb0140b278324609c4a4cb0287ffa33422bfc05ce2212a5329e4f49dd3bc37192b6f78f2cbee9f1cc888a1" },
                { "bg", "3cb7fc21df75371b275140ce4614a549366e4120cfc7caf090ca12435a56f7821905ac50af3a8c9c0f988aec92bd6c85b90d242ce2cb755059843511ceb095be" },
                { "bn", "6ac08418de41ab1aa808cd77950698937806cc9f6a6f7c6cfbbdc27db17aaeadd399a8d6e65054a7295c0653753cc396df0697a484b5e116308c288e5339cf06" },
                { "br", "2f409cffe6020e79ce540826ada16b26a2ff6a758ab8185ff3dc010e938cac4e4c16a7a7cf9c940a465f448a4b24583cc4899c189590ecdf4b7629889e9d60d0" },
                { "bs", "e2d8d58d6e8680847af4323c19534a7206216c1bde7c09d80d156f1dfb36871a0c99bdac6114b160e11784d54e7e3484b906eb46411e63f7fc34fce8cca648c9" },
                { "ca", "5bdfc9007fd55fc9ba31929b4d637dbb2b95cd6332bb82148f669c509453d78d09e182f263495016dfb17a37e6c7b99b8b2d3e4b58f4f14307cf1c2974389a17" },
                { "cak", "7b0ec7628fa4b0ad90abef9af83ad07c5dbd7dfbef69a710b6861366f6883dc3e462b6e72f6eaf218406aa0b7ab5430e30a987fe2e6e8f2e0ee94ef5456dfc22" },
                { "cs", "1d9170b1adb84032b3358e98bd9c9ebad48169d3a9d9655caa0b7b5287eaa0ab9a17225734398977a846833fa04819c06fdfc62afa8926570dd8c743c71b0fb4" },
                { "cy", "cea70cbaced2f64227856ce44259fbf47f514170a7ad622a52efaa6bd2f01aff3cd9c1cc85adfba9df1f66036b1e621dd80eee109e43a9479c869c5bdf7abb80" },
                { "da", "b93792283ead4ce4bd94806925350914818ed97639224986c2ff081892f58843f8f0cee17c5d33b885f09d6e662bb36083900150c24c371bc36c78aad0d184cd" },
                { "de", "7e2e3e28572fc5392c60267d24cf06a11d3533e5e061ff9b8a3dfa24d016251b064d038b6ff706da69d04125f9a9d7ad96551113efa06f0ad07268704d927621" },
                { "dsb", "9154bb5124bb020b82fc7a3e24b3754d9eeec45797cc4125e44e30464f8c1422098e5772d34a2b60f9b1631b86d5d003f80aa3213a0bb39bc755a6b4b4b2a83f" },
                { "el", "592d6ad6d26e0ea3afd9a91f6d9a2481643e5c8fd41716037c3033f3d39bd1033de48c4089b5dde278a16d924632cd8b1fa5c04ce839b12d38a816f94ff412ae" },
                { "en-CA", "4134e0b13d7d231e136e0fc5ffd7f6759a8c0686525e92b800c5ee7fd26ab7d8bb163b64dd0eea871efa9f7dfcfb5c7178c84e528ce10417404fe94fc76cd1f8" },
                { "en-GB", "3514f18a6551ceda8e75afd6c35f231b10b9083351accd6099ce13f5dfcb0b5e8c3cf70c867f6086551718726d07c4978e0d54f5c80fc895e3998175c2f42582" },
                { "en-US", "3b676a4f0078f672dfc40e36662cfa077a4a1f0538d4a694add120eb28baa0f6b1631aa3cbd2d51c316cbbcc92f936e340ce124d3dbaac1de94530e3c89c5ffe" },
                { "eo", "055c9b251daf8cd133a31e2c28aa428502a44d3181e99f9ac760494f4117057015351621b1f2533dfc031f82bd8a4d2274dc39316c7709c13668b0e8ba279d24" },
                { "es-AR", "2ed783581c7d18d8abdaa33bbdb8c98da50596df40f7c1bdeb99440d5c8aa2c8c39cec882101ce27d0ee4da00e4aed2852e6eb632b8641f0c0d0f29c511ceac7" },
                { "es-CL", "4165884955bca0d25fbc02281def03cc3b557875c2a1f399565b2a8093bd130f6460ff249e89efb4f931ef828f63e11eab054768177358ffc2456c11875dfc0a" },
                { "es-ES", "05bd03aa2b65c86cc7db6e4de50fe3cf13e25476c13cc239f92698131c3e1ecd5d1b1e8447e7c1622bcb932dd43203fcbd926e6735c9307643f0704d71156091" },
                { "es-MX", "d9f29dc1701232552c7d0eef6ccfd1ea1798a4a57faeefda75c89dccab41edf5456d97525269243e4d5dde54dc863c29d4af2db8989209670f6c85d0d575c0f8" },
                { "et", "c23d833766b1cb808dcb6ac610be99227547ac60b260e998163d4c73364898ae443ce185e38f32c45b7d53ede4be5a491c3d2742f3240593a3b4725b54d756dc" },
                { "eu", "ea6376ec575a619b81a747f601ece7e4d614fc77f943f14d4b66517dc375c67b795b5655b8bab6518489e1774870e8354dc65284bbc8626de20175a276a86687" },
                { "fa", "fe5da8379a9947fa09c896f042112dca2f3c84e235208f62f7c07c366d8f08b2d408a75b744fe1408a9e12bfe9bab1540a40efce2664fcbdffd87ba81b2b7313" },
                { "ff", "0a8ba7effd2d2183fbeb4ccddbfc9136e09a0c201fec210cffbd0da35846d82147076e7c347bf467539e053e73f01546ca70165df9bd7fd68ccfd5271108dfa6" },
                { "fi", "31d9a1e479b3866a14f5dead03dffdcb7dbc369f985da98556498a112af439575885514ec782edfb739e66a8ba282c7332762d8378ed4bb070131fe009dc5df3" },
                { "fr", "352cc47a6c8b8078fa9820c95fe3a06775c973ae2c2143f09ec30d35829bbcd88ffec796ca2650d873838f036b3e21b31e2775e40573415f4cb45f1810008677" },
                { "fur", "a7c825d29212fee307e72c651310da1da8d739a142d90e39661792feb8800dddd19e218e4fb27c2572e4942d4e8e65c60a11ded165e1c9bc113727fa31e3fe76" },
                { "fy-NL", "f170255789198f1ea28dd03f1eacd7a7d85bddc81c50f976c777e65a43599fb45aa6253f6acfd41a860bc8c35f937b83f6807ad79f2639c9493dbf32b8da2e1a" },
                { "ga-IE", "0dcd5c3486a30c634765ce21619649ed61bf061b366be3f48910a3d626b3c672bb7268a929a0f02c672554983f488e7f0435645334c7a39748f1210deec70175" },
                { "gd", "19fbfbd5b2d61fec0421030b195a82de11b8abe7eba4b4ba6d9ef31f0f3340c94999d7f2904ac570e490c6d9d4f2913dd232bc6e5cc3161c442b892762025ddc" },
                { "gl", "5a44732bb4494c1309ef85f8bd551f85e75791e61b91cbd281748dc169dc4f4cbed91a37305ad25dd1244be0f2709847fe1d5ea87c09e74d7825a4844470212c" },
                { "gn", "d47339ad3b2db5f14841e11fee52b53d402df0d1bb0435627a94e669dd530d59f846d0b896c96125dd212f37edbe57e2a7dad43f71e9f1906b89ef330ba220b9" },
                { "gu-IN", "5e827697e64274dcad10f645ff84337dddad12a65cd2232d915ae971b9502dc9931f32f5039f7abad8802fd48d0cd5294c49deb72b261e36f4bcc75fa47281e6" },
                { "he", "00ed1945111c18c560bcbd6bf9994120b467356a5a96c75e93a39c7bf5cd2b0c8d8f9801274e55a5415b138ab227a5f53c38008f6b0150d9506c320d7351d3a3" },
                { "hi-IN", "311c178094fe8fcfaf978f03077a848f20fa9b8b464af4f2f38733a736bdeac2cc52a4217ee9ca569cbb2ef64bf523a55ceca814c7390d021c6f564d244a1d2c" },
                { "hr", "c6666fea2d8040fdd3d78cad928ff8cacae02e50e48f38e660afb02f5e5a33dcebf860491ab74bbd9668500e17b2b72870c902e7d4edae0a5e44156b110182a7" },
                { "hsb", "c4e87237bd5dbeb1d07b4ca888576d9604fb0b96d9e4b13fd32e169aef16e56859dba9beb30f87c288b9f928d0e73e34f116ec908f982ef22082d4f835b56a49" },
                { "hu", "7db8ed3ec1e345bc77bb4c71ebfd66165347b3712de91d2e590e46500ddac4ebbd57b4b62a6b57da39a3ff60534687304c5c8b226d95837455b368ae41dcfcdd" },
                { "hy-AM", "83eeb513ab7cb1e3da746b7d5d26b36cc6c45ec8b8d65dc1875432b293655d6bf7c75f29ba72986cb02b9ebc0048be3dc7aa16495e6674a71ca0c4277146a181" },
                { "ia", "07ce04784b74931d263630c8ebd77dcec64ccaf8ae8477dbcea437b8e666685d3018414f920f607c41cb8d07129ff458fcfd2c8d5da9af0529bc57c40c4ca057" },
                { "id", "0267aeeeaf2de8023b4776548787c0fa32db73743f7c70ddcb826cecb8c28051c2582b7ea5e78f95918be85185c999aebfc1f15f45458406f4fb81db160a0611" },
                { "is", "601257c91da6b94d5eff15b2ad0e3e9772861cd8b22341f6e439816f482267a7a8a05a49e18b13ed63ea58c980be5e09190a9e855c020dd5b0053ed73dcb7781" },
                { "it", "fbdd8f4a647948203bd7b58941a074398abf10217a8cd89206cf96756387f11376c02a3d8b65fdf91dcf4275993407673a56f06b7166e625906b0e4b3278ed39" },
                { "ja", "576cf9d32690fd911b2559a9f77e29326bab79f0fe0d37df8b0aebf14edc2290f29cf2642943e7adb27c7f9d8dcd853d0675cc3fb3572136f872055a8828ce93" },
                { "ka", "c7f5ed9d8ac846a0b8428ff55747409d785176527fe979929343ace8223a0b7567f1edd31be6c51618f5b620a392e1aa0d9a6a0ca3fe478319eb0587fcc97754" },
                { "kab", "96824dc1bb6ce7e33da38a6eb39ddc9614569259a43ae1b853d4aa23b729ac4616f75147657aa789205fd5206cb0be4db0d8fe44e330c93762175e757cb08fdf" },
                { "kk", "7fb22487a40a4feecf793f5063cbdf75f90586783b613b1d255bd53174c41676f73d0e22dd10e93e5b0fbbcc2ab22f96d0ddd1c302caec3b4ac4b1525af1a37c" },
                { "km", "138eaecd3966428b896f6aecf6bc6895265e4b3e73870115c43e714f196559e057455a58a0a9be63d5d41c11b1fcad1663eddc74882f3d668ac09c69d328cfde" },
                { "kn", "b108caa526485d25b041cdcf4c9ca75f481bdc6a2c4c4be83bd431e4a3b3d586e03607059469d0b88ef6660c981bbc6b058a3cd2d56650184ef6048c1e71380d" },
                { "ko", "480da1b509769d04080cb7120667c478c80540dd31cc3700a8935eb382818dda00759b6ef0ab2326728d8afc49c27f290ec513e97c5b220b51d8f8a59bcfeb46" },
                { "lij", "7f626720a830386252be7affd5d14d7779f2f6a9eebc0df836cfdd53569fde120aa800fa45ba74834225071288f0a0f589a14250796abeae51358cbca98a66f6" },
                { "lt", "c1a0596d11a8214a9430dd1837767ffb5ee32a0ddcf0e9e04051772fc2e27c51cf492376504d6b3e233fda4ceff7e5f6ee3808c507ca19b6a70f6637b294929c" },
                { "lv", "b630ac09ac4444519dd5d9db4dc3516ada5cb5cff277eb79d16e9017b1291a29378c9b54458178fae09a44cae2a66860a1851fe9990e103e32551e43b82de61e" },
                { "mk", "03e2b6d1188b38271de75fd4c568b4c53f772964142b469e9d1117cddaff9d621b513b60101bfcff1996d2c20ab86792848f4126f05620ebabe542f626b9b898" },
                { "mr", "2317ea7a7e1078ca2adb44fa8612c05a7ab426bcae999038b26ff1fc2a4e82462c2cba2a39286f45df703eb1d3166f8927e96453a30acbf3bce1066d732911f9" },
                { "ms", "4f571a92facfcedf4c5c9b15ad7632273dcb751d22c3f32002cca71a217f0a9e744cfce4f6cb63bf05a01730fb87f1df660b5692f041cd11a12f6954f7aaf294" },
                { "my", "b303dfdc01af8676d90b248f645f9171dff6835eb6a41090cf5c31eebbe28a422da72355cc2ec484a230b3b75854e3d2c772fde559112fb3f669a675052358ae" },
                { "nb-NO", "035e638be8b2b8388147be38ec3b3f6e33515803c7ad90fd7fc7e2de671b750a361c10ff4c5b39a8af2ac3c133d21a3cb888a6bd78db4f0c44d69230d8cd951b" },
                { "ne-NP", "ca3585beadfa087de2698aa1ed325cb06c6b5c6650a6d4e106c2d1041f1b30fb9aaacb81652e88259c08583fb4b9241d6cb4ae9c5dea444cdeb6cd7a07695fbc" },
                { "nl", "93aff864d208e10973127a5f2c874626baf37bb1ab9c613d4adf8336fee29c9ec78d19b32750634bdd2fa711ece68c94a132bf11c537f163e2d8527af15ab830" },
                { "nn-NO", "d200f6448d035a6bb652c4025aaf713e14fc0c32674ef810f8b9b2f7f75fe581162bba600c390aa732ca13417d22adc42c9c43827248846d012f6a67ede85060" },
                { "oc", "c25d9107f5462e637a6d4ba53813743126ae4cda58e527db2c0384302570caf769471b3fc8112e2630246c22790b0ff719f477f25ab4d30971321baeec83c2ad" },
                { "pa-IN", "e0784709e1e4cf53f7aee0e05a14c93f613639a9e959998c989dc12bce87b49014a46263f11cf766f64e448ed6bb3e152113f3eff90027f90c7afdc3ff7b2a8c" },
                { "pl", "adc57cec08c5429e7aa2304911182a53424de316b893141fdbef8b628dfa879b939dcc3600e3ad194e887a0ee362b6451c7d1e70978734e310ca8540e354dde1" },
                { "pt-BR", "f87e0a9ebfd9755a8e1f45b6181893f215d6e52325d98dfed2a2df0cdc745f360000356a4669c78c498c1aa652ef9500558ba63cd5b026b78f1467995ec03e81" },
                { "pt-PT", "d000a62f0eda87b06f59cd4dd185894d59f43976a625315d78a476354050faec0f09786889bc6a20f6fc7c9a534365b6868a179d6c4a389d5a43c59647b95bec" },
                { "rm", "09bae45016248c9b15537c3592123eb63e9ec7d9af0f0ebe4d626b8c5f649f182fc903e29383e44016cc1e6cd0969a91e8cf4b69ecb51531f21762eeaaaeec51" },
                { "ro", "53a7f3a73115e0faa544c6884116e65e269a3339964e1322b7d70ed06b08bbe36e797318469570acd0cbc97ac58ea606cbbbd767183d01915a849842cb794bda" },
                { "ru", "46184ed8a1576f952cf2a26597a3144f3f4f7db8f0acd44048fa94b962dfb4bb9b2c84bd7973978977c342f69ff8dbb48ca330ab6d8f078db7fdec13c6f511b3" },
                { "sat", "d4c195c9ce0989cdf0f4d745d595954190730603d78723bcf89fab976968495e006e517771e6e343d0e6bfdcc3f6ee9663acb2dc3d0733025078d1bb87136533" },
                { "sc", "6527e6378416be8ecf8b2a63ffec17b00d27c107fe95e1311f09920b45473ec32c9e4a1cdc0a176457acbfef88da198ae994d487c30a6d3360752a620d16cd38" },
                { "sco", "fc8a389efd8b6165c5a2c644a6fd0760e07fd4af065307a99e9697a96780341e6fe086ed90b73849e1f53ba2eed642bd7afa2ba346c10aded244f75321328e84" },
                { "si", "d5d17aed3981134635295474377a12570dd46fe553a9ee66934fc67b13df5dfa06dbc0592f22ff9916d9dcb25908cac014fc74cfa048e96c60804a5e42defc6a" },
                { "sk", "ca8d521a87aea9adc345a9880cbaf7d22b768224c1ea80341592d1e1d838e41e755bca266995389b23d47a0c2a44a7aadbaa20deef8d2f974c42bbb3cc79c984" },
                { "skr", "2fa275549f993fff914a37d77f6e040ebaea965a210db3a2e8d3ae47f402e164530dfd93f1ea99aa2dd60f974c59c97b45b21c19d10b66ad6751d28237138b9c" },
                { "sl", "1a93bae1900c6c6200769aedd2d4a4d5a890580c336546ddc185b3e0d43688007639d881a141741d00d05678314203ff73d349a8c642fc3565116d3ab75ec8c8" },
                { "son", "fb26c1095904a1e05f9e6ae80d8a63b13a435816bbdbf941def65f097fa2464e0de6c6d5a51d0137a12eb71c0d17bccaa2586e2a1db3d94d77237c2cf7315b46" },
                { "sq", "1bb6674eebc17c88bed17ced2d382baedc1420b12bcf9dbaad87a0fd5c5b8126571f8b6dc1a37444caf60a9d76a96f41c5d4cf50511f811f42907e99226f5615" },
                { "sr", "c58b1f4348b65562f06319fcf13caaae3dce22e972ecc828593f35bb35f1fd6f3f230ebe592a8c06986163a2c5e879ce0da2ab77f8c56616a0961431ef53da21" },
                { "sv-SE", "08dffd48a31266edab16c966256ef0f4bccff562a58368baa49c6ba6faf4d639b45c269ff69ef02310b4a541979fadf8d81228d4c762dc67aefbd24a6e80f0e7" },
                { "szl", "13378cb66477d177095812dffc672a660834c18b597fafc72b9c1c549f74c1b26629c781d076cd6f637179547e7654127c1d590a554cea08222ce74d31c20517" },
                { "ta", "fe2265cfcf37073a67c21b2e300deff336ceaa4309fa32f5993be618ed0877d1cba220dbf028b5135a638c3d71392974879953816941cf935e97d1a3ed7b9704" },
                { "te", "0cd0da4d9fd70d0a7ceabead5cd29ef8e0168d1cd986f82acdb261d02b580b2706f581b2fa4e5b23adffb870c0a640394749a4ebbe55fc8b00260c8d6bd69e78" },
                { "tg", "ee133938f26745ca5fa77b10febe4856f0e8ec405d50325c6e686c8d3f87c65c5a3120ee42a31e77f16e449ca51188e31275e9e867420bda0d0a5153b0575bb3" },
                { "th", "5dc7d5cbccdda32be95115977815521dc69fa0de917699ba9e10299727a839620ebbaa08205b45cabf95874109d6d5e0da0161a01cde9463a58cca173a65138a" },
                { "tl", "f8525e2a22869b78405a6f69ea7792349699e7987bca3782a0131aceeb6ea4a35cc4f840f4cff58ae9faa73e089a9e8a98e611f9e70b45035cc8680691b66ac3" },
                { "tr", "eb1926595dc0ba09df2833b9459b9d4e9b1f3536d7e521eb3aada1e48f99ad4f5829bc173a22de56bb303b830eee715c2aae5364fe80df9b137a773ad8692c25" },
                { "trs", "166283d8a6256eb1008a4132d476e7b7ffce31c9c89b4c671331365eacf91eaf470c9980a861f106775cb36ff66800c0a4bab99d08dba3f6702683b985962dda" },
                { "uk", "3f5f2bb0c01aaf1700f49fb15c59b05d7180549ba7a114151c541e2cc4b2ebedc08988acc7ce2fb9bb92731599b5c8b755bf91b4e90f63bb4db304b20916f1d0" },
                { "ur", "5f18b9b493a3a7c7c7cf394fe55d373d43cf8055e8a4899e8ffdd85b9878b0110e9530d8e5653a9c42081a5c4cfdfa1f7952bbf5686fbf6400eb89a3cf8b1a72" },
                { "uz", "8d9511c2eac65959b8c632a6458c2ac92a9780e69d0b9dcc10ecceb4faecf5a662c191e88bc3f9f53d42f651c38c8874ee9b0defb1eb86c767f2a8e2ae957aa3" },
                { "vi", "0aac2d3fed544135bb7535a0a82492f92f766cc7be8b54b7cf77a8a8a5a7d052c8eacf77334e961787f2b4b776c7b8d288d45d7448057631c9b0885db5f42711" },
                { "xh", "d1f19804e69258a3105fa4fac54066090dccee45023f5c72040ad94d27710e8dc1d32ac7dd42c5074150aaca895c0feb25f34d413758066d9997735a8aa8638c" },
                { "zh-CN", "cecae05b27f3ca3421e8cc2a8a44fff6a8a40e89520dc9452d509c471e285bc92c5f316f83d52230a65c3a4ae3a85b557ac66f157298993e5eb9a6a81179e16d" },
                { "zh-TW", "c71f6f04c0c9b50d8b8f0bfa8ba9a74d15c2bdc0c85e166e09160df4814a7434da3c8988f5d3432740277f27e631c9536cac16a0b0d7a8658a9c82533bbcbdc1" }
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
