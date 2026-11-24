/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020 - 2026  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/firefox/releases/161.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "897702f8f2bb592de02d89e2e7d09acf106a5a7c3fb973a1b1a1d9e6672376b15f7501679896ffb992b8ac16c6dd81136e3a06da2c9c65722a03e0e9a2a81690" },
                { "af", "f233c60fa552bf3e84930b024dcdfaf49d1c7100c68080b82d3d3d296600efa340b75d6a9663644d604effea683401895bfeedce847eb94eb2308f38e5867aba" },
                { "an", "a23737eabc0b2762dd3810d7b5cf973bb87e69966ecb549a889695e1d562b1bfe4cc8c125f12ce669aec0a845827fb313fc8b88a89e938e4c38a894695a69a06" },
                { "ar", "b814337e907b2d9f0f94f58327b70771804dced3aa2c7a844234cc9250cfe3d505ee6c17c8fe3a63d89634451c37a13ca2cb429f5a599dcbf321f3507ab2f518" },
                { "ast", "b2041e16f7a3c4a4cc5a4b3a61d7c084a20a556d5b620711953d254e2adc8e94727e447d860554fb530b520576ab8d94541a409227463bfb4a81ae0dff2247d3" },
                { "az", "0cd101e4f4dfc43438aa10960febe012768a2d89e449b9eba04631137cc63401305b5eb3c34043478ccda6d76207937e77c9602cbfcaaa80fa5f0bf0758be692" },
                { "be", "ef5c6215c8a6acf4315983edccf3b374f7cb757ae7d66dcb61a1ade46e52cb725d34845b704b460a51c20a9d4aaa8e4686105e33a6c4f564da232b8488f91aa8" },
                { "bg", "39935eee3f21907240f41702f3d4954df50265b802a783bc50aa86b84fd3ab7a36b788c989fef220c57a85a79b17349c4122c99815b57a2bad9dd6074f2e70ae" },
                { "bn", "8a640692cfd7dcdf87eb6cbce8f7c1cd7cb9a3e2eafcc0a4bc22de905688ee0de74bd7f5d84f14e2f514014edd4678b93341a9d2e1e9f67b2591713474e54b47" },
                { "br", "2432992f3f326bf641943afca07089f72b6bd30bb8e1b406bb143ea20ab9c99d43870914f84a49e88d9c224ffdc4de333103df20df830f780a4c39c3b6dc858a" },
                { "bs", "0a75bf1e5c266f33d14e6a8830f454029a027b0a98fd551fb4ca3af3e1c4d6a32d897e29627a43be19abe5273b2f163fb100d072454b7301eacca3bcb20ff25a" },
                { "ca", "dca71b3a4820c799c615b7fc53720fd409be32ad79c69712d181ee8a297493862fc5040850b6c99faaf31965a010f18c363432bd9fb89e44dadab5d9318ec1fa" },
                { "cak", "c71a31626df4bc419aa854580848bc3bde7035d42b482a0cee3baf1bed1e13b43400b52f979711e6116ba5967ca2f5ea39e16128d967bd16fdf3bb67b3c53dd0" },
                { "cs", "54f6cdd6319c4717a5310e07fddf97e20c3d8fdce9e1c30083787ddc8f36de8a046ee400eba6a43e1d1ffd06b1cc92179bf0c247532fba5e01c7dce282480769" },
                { "cy", "07ce385b280d44e2b8db71507a3edb108b02b2ff0154be042cd4551bfb4f5f5d9122e46b509b329aae8f8dc0d186f2c35b851959d1fb7bd6819c14c5112c843a" },
                { "da", "4192b86ee3a2f8b93c62124f82051642bb81bb639e098d3469c028b4f84fc6f2cbeb9ae73c04a80ffca6ab29c90f5a093c7dd22023ca8b94ead5380d89559b9e" },
                { "de", "a82db76269db0029454cef342679591784dd51fc8764b32878e078b6264bd57697f25f92685649573809c95dd5b6893cec734149cf397c6968f4ea2ea3a92ea5" },
                { "dsb", "3f94d1d289aedee17001e806b1f2d94e155edc36b969a554223df1c7e0ddae1105f44b7d96cf3ef4fe47ada73efddcdd11be9eb826d96536fdd85d1dd135f3fe" },
                { "el", "ee348165d30397b29766bf9a7a72fb98264df2c6921815d3d788a619df1028d72c46a5a4a0e725c0c547d16fa9b7fcfb75ed0d5601bf639c8c8ebd0b3918649c" },
                { "en-CA", "f04949d0921e0cb85c41148403e68ea47ebbaa6bc70948c3b1686e83bcfeadb897ad27bcfe93d0e2680e486bcf24ca28754d47414227a259b3cd00cc7ad51aea" },
                { "en-GB", "10e7f999a066c26a4ae32e8e2d5ed8c53c6cfa73a2f793db4f1d19883fadeb5426897331182301ac6d663d088ba63a8ecaa696e080448244d008e7375fbc100e" },
                { "en-US", "84ccbd11cf720291b574b2535d58ad5ac7952b303dfa976ab405967631151e921472739cd906a835559fc87d4f4c7fc6d546f1391f49a19714fb47520f6e854c" },
                { "eo", "d753e63733fa7aac68f229f49bfa7f6a671b407338341a968601c9d99905b603b6fb7bf3894e3cfeb9de892f49af5323378fde27e61925c7b9ccec22e43c6bfa" },
                { "es-AR", "3d6dfae92a1dbf0042e2ac6aa5eba368731367b81792f9bea8851ab012c1aa375856f4925a5c1170b9ce6c2f753dda0091fe9faeeca1f2d088c64ada16f20c0a" },
                { "es-CL", "819da3fa0c70c3d4becd8f10b852727c66270ae4d3e6053689fbb93d1d19c8ba4f386b44638576e2237024a4804924d143907ee7c9bef5df9f908f50e790a374" },
                { "es-ES", "71025c586b784dd1b80045505be39c44069df7d25a090e354c39a004042bee9a08047f40d5ef8443dca62703db3d78ca7e7ee1f43a234ff78d2a411ddad5ccf5" },
                { "es-MX", "ab1db6e7eb604a6a9d86bca79ce50b7f62cd4a322eae2211787f79e9efd279f508f308de185547d807b26d0e27e81798a299a97ca0874fe067385e421812921b" },
                { "et", "7eeabf5b0a501306d86ca20632bda1c2438bde6a883edf85f2d3f4ec026f8ffd63c343d8738e3e11af6e62c0a89634bb064e4f403f00b0af0917fe9001865fdf" },
                { "eu", "7ee4253b26ae02b0c90e846c4221506bc3d24f604da4b08525e918ed2bc20765677296fa5b2d588f33c73f472dd932da16dacf7de1d8d9a85ce34544c77087c9" },
                { "fa", "9dd5fc1d517f9de8f319768ff22dd50ecddc862108544b6d69df7b44e8bff88125f115b489b89ed9d27df87063134b2a7cff6de5766379b49e2776f048f5ba9b" },
                { "ff", "70e7c3fde2779330cecae74b1c71b1b3fe6bf88e7b64c66bf4bfbd75890b4cfb541b5176922e817320752c8d1c3ac06149bb7a3283b2654b27d27fccc03ba84e" },
                { "fi", "4d449496302e5662e274874ca8459a3b96380959edc80ed854f37f38836936d83301c0a4605215879f16509e376e508fcc7c6558e57b0a13aca0b47c7ccc9c2d" },
                { "fr", "9721e93af76c23551615e8abc1362c63c1bbaf2eb6bf95c38d75ac220574ffbe0ac64f3d15759a4891db6a6a6137161aa8885a5e67aea668e9c3ecf43f9c062b" },
                { "fur", "c6cefbea01d4add42ad0f8eba39ad691a809e74a63fc8968f9fbb8be2b8adf986f1cd7c4614a46462475dde6b3a35bf5bc87de292f0ca50f1306ebb7e0cf95d9" },
                { "fy-NL", "fd40278d13db3c441c1b00f64e3d9dc06d02f35290f6b69cbeeb8e1b1074a2fe1487f246de0445d8261dedf5bca2698e1308da4fb006126270e73c1bcf241f8a" },
                { "ga-IE", "f5ec34fcb5a81385fdbb55b99b74bcc402917810d54d6acca68d12c8e1db1701b54fc8699646bbb0d8a5de77e225c5b0d9288b47018cb9c09b88b785e08d6788" },
                { "gd", "3ba6506c10b4aa4782474f87b7eef8ccd7f23989cc8c6d516d28317aec4ee8c670543499a08833413d1aa39016ddcf8dbfdeb0fcb46aa060b536bb4ab0063eab" },
                { "gl", "9e476fc649dfca57b0a1f7425244dac6e7eb049d9b6cc5768345246692c67b6b7c8ebdd92ab597ca4186f9e322cb7613afa484ae9de498f1e9fee9e9f80e999c" },
                { "gn", "a716eb2a0c1fbc3f71e599151fafd5e7b69973aefcae3e886432a0c1f87dbc17f3573de2e84349c7326172908070e981077572bea87d9a7a08379128157fbde8" },
                { "gu-IN", "8df88acd08d068bce61b144cd208fb63dc574833e587acaa4d3e8d02f0d1c449591ec6e9348ba88111af95c5acbbe76dd83182eb1c0701ac3cdb6fee31d0449f" },
                { "he", "8b5894d4b5f8db84cd97fa591d01f8ce86cdd159d1f8de59b5b7c7c74c1baadee03a9d2308f9058e8b2f441dbfee5c8856ba7b3a251028baf99468bb5c894d7b" },
                { "hi-IN", "b302b0d36f733d0f90b8527f5cb52e1f8f3e0ec40993e4d82f25efff61f0afba915f0806e32dae3698c412295098d7a38c0c914a2e2ca3312bdf99a27a949ed1" },
                { "hr", "3a56c7e6d9774869d6dd8221f73c5f26c6b841431a078d9ba9d081618db4a488f3f1ef4dab2090375e0fd887354a6de76bada5c0bd7914b7ab0308dff3bc6c26" },
                { "hsb", "5b551ea23bf854cd9b505b38e8ad9298b708a1535529c4adac126ade0c5fd477d8ac528d91190633ac829b039954375056a51d7f17536b067d3ff736a905644d" },
                { "hu", "5aa0e39ec5d326178e8817ce454bd0fa972eda03938e2ffaf1f715f5c52904f6a639dced80c3c54e63d39f911c98f2eef73e46fd5e7248e3556fd8fd1d7ebfc4" },
                { "hy-AM", "359cf5f1568a8907188b81cac342067106502622572ceb5cfad0d52616506499669acd82f0dce1d0d24cb9f70b962288a9dbfc4f1d7da1c094a194c693b8efe2" },
                { "ia", "5d801750d16e4074d3d61e929a4e359019ba8c9f4ea6729449e4c0354f023df117a60ac295ee476c713747fae65cfe14dce264098f3c4cd405451d58cc59c597" },
                { "id", "bbb8bb84c13b617e0779d7ed814d8bfa5fd6277e43d5cfe52373eb95eb55cf5a8647914305f9c0d6f387b454b3f86c6014449deeb960520eb53a2babe1733f35" },
                { "is", "0e9a2ce9f1115ec073f9eb29718e4a5e5853f6e8ee4d328aaf4cc2cea3da2727e32d7ecd58ec39e41233b430182dbd2e2552ef19df7b404a814638a3eba936d9" },
                { "it", "3e7cea248e99823aebfb6c674480774a6782f7a108eb50d4631d43afab00a57428044d91376777eb2269d04a744fcd337b8f74505b3fe7ee76a5eb714fd9bf22" },
                { "ja", "f78b90f770c38f86500f12154535ba5fd39a2e02d65fd5116e2f8d5f76625069d82f275cd9500ca47b7ca87040a4453b85f3a0af44f2ae2fa2093d7acca04904" },
                { "ka", "ed32168d4238e5e729e0b57beafafa99cc30050e2d6ba07c2082e01367b212ad3b65b6043ed9848f792bdce9fd3f4c3191d288bd066bc4ab4cd1954c640b9fbb" },
                { "kab", "5c30cb1c59e51f7a6020dc2956b0c2b59748dc55b626201c6f08972ff78836579a4066c8f8c6ef05a1a01a214f04d705c2db2bccb65aea74829470bdaaab7b91" },
                { "kk", "ce5c30191a7df0e798e0a467c57624d9f1b21c3934064f9ec66af0d5146fd2b2b5e4c397a578ac598962fc9c9cde26b53f2c66185b3bf7cd80abbec92317b7bf" },
                { "km", "66a32142369d95f8f2909e4ece4ff0df9f1fa9ad20421bec9c3de2fa589498ff28ad38885640427797408a19c245beaf25c3d2f6938dfa15925c1fb0e6749578" },
                { "kn", "7c00eab0dac56a2aedf959e240a906b9f0f7ce497cf3fe5c538cd5ade5f890c0a507bd43a565fae927c75d8fcd879aac6eb87f6fe10e8193883a0fdb409b42ab" },
                { "ko", "6750f49fd0ebd18311b21ad6742e98523fe6d8f6d413b83782af968207e77c78cc6ff138304e84edfa389e7ac07a77d2dc883cbbd90353b2593cd7f6a6a1db9c" },
                { "lij", "650410862a8f6f8a8286eba79150e40fc811f35ac0dd3a8f9c176d8c53505b49e3907b43bcc4015062823d335dfb72d55924a7f3e1b9a57724e711716bfa2033" },
                { "lt", "570edf01209a30d69e28992dd3225ad21345bdf849990800f3811e90dc6c04440e6bdc58256f568ee70c0442b77ee75d729bea8a5a75b1e5bd9782fd7c253662" },
                { "lv", "c692f5777f76ac36a2f77805b786363928da3f79c700acc71cb923900697109f034c9fa0b909934ebe685fe32d52a237e3b71c08432fcf5e467727c1e6f7ff85" },
                { "mk", "10b6db93b2829f40b0393e0d88e17b3ddd376759bc1201cae2faaac5cc8f0b514b7a22542aef12c6899612781d45943eb9e848c903b410a407fdc68ff3d1a9bc" },
                { "mr", "9c3490d2c9c64afcab467312d197b5ea0660c156d08310a9bac1ffdc7862090bf439a93c1d730f9dc0e8596b2e33d494a54b294a13a65e9215fa7eb6cbec626c" },
                { "ms", "02a261c7cbe4eef3a8e52e0426539dfef1cbc9591c5aced68a0ee3aea39f8f69bed59c93222ad8eaa8cbac885f9274995fdb1f3dd199e2683940d7f1d3e236f6" },
                { "my", "cf03af237eed6bb4da35919cf15ab97f40f8faf64ff7ab22eee67df6edad4a8d1580377625156afbb495f78a36124b280864155d9fb2eea67b6c5ea40f7057ef" },
                { "nb-NO", "fcf7184126238d1415f905bc2881215f266bdf16e870a1c5b40e05d6dcddb5a1439384098d97f5f8124ef39d037b4832eafe35257d0bc04f548ab1f60c84ca1f" },
                { "ne-NP", "74b253e4fcdde83a1dfe2e22db0f9fd3fafc66cc1464e26a93fad14b5fef656e31318d2009f2c8c69b2e6ebef10a5147b352582992e824b7a0608841b8471ea5" },
                { "nl", "fb85110de18939281d65d93629629b6445860ffd795f3e683bbf267f11254465bfed1d477b3f18a5c91662df9eacc3bea151a8ceaec480a4abb6d4b17b11e8be" },
                { "nn-NO", "3f1ba29b511e596c892196d3caffaa15a35191c1a07caf557725135d9d3d07358bfd8884de40a946ddeebb19696103a59e3c43d3071a6ec526da9cf28d2da362" },
                { "oc", "cc6402c130561620a6aa1d0c7b06fb67a635125bcb8f4c1890b3917a62f3747f3d602fff2931c331ae9c772215004c1cd8a2a33b59b6964ffb692e8392f4774f" },
                { "pa-IN", "a42eed50854f8a032de4eba66ab53144bf65e2ed949b18ca165d239ef24c5133946b92861eff28f65aa0229405a14e19ec369d30214ceb7872382372b5d63fd6" },
                { "pl", "c2e80393f57e9d2fb4e9441d48780cd94fd0d7040b4205d779f49e5b7b038d3eeb1b68f29fd305924d062315e98db542ad694908622b6e467df1ecfffbb67cbf" },
                { "pt-BR", "f92f3930a40377725c2d49d85d7da4b92c117a239f1c45e9e0032083802734898db6b2d6f978efb2b32b196c01bd3c2281d5adfa978d2f340306ee3ae4b8aecf" },
                { "pt-PT", "3de314a5cff29b6b3a83cc04c91b53861b1e1fee485f8f836fa7ce077dbdd36ed32cb29c7403642f1045da05f8eb54d83bee6d318cc8a43eaf70adde22c0b315" },
                { "rm", "3aa64ec5a7e62c8a71edf336e951a926ef0e78156692d3c83db0a256ff81687a8d2959363dfde027bf8e59adee9e619cf54a4ff580f3b8f5dd72618384088b15" },
                { "ro", "2f37b1b9f8f48b3dc9fa5de552616d289a0f360c0508cc290403350f3cd0762f8ec0d979439f7be31d0dc06065878c2e22991d1c0273a973e6d1f112863bc239" },
                { "ru", "e6a38644cc6ec033edc4dad224812463fb873228436cd0c63a8c51278b796c4bceac4d741969b86f82da7680fbf802fbc1daf58c8146a874910628ecdbddfbcd" },
                { "sat", "4b37d3afed8d3986fd9c4c26fd11991735316ef18c8e2524a65a57474abebe937bbacdca893cf2707ee2d336f3095339e7b5ed923baaac00cab3fa0759355982" },
                { "sc", "97799a111814c9d65adb7d52bf2b8f05f11d50d855b0e4e7ef86906a3db406c4cfd64854c61d1b1826677f56591558f2bba9ea79fd6c9b6330b285a5267afce7" },
                { "sco", "60044427dd6625dd67efdad025a5ad2652f9c9b838998e2333ba7a063ef3d59e983bd99487a3e50604953fc8de1ac3c7646dc55985929c440e18778bc3d4be90" },
                { "si", "79244283f822a851a2a231217cee65c74e178d1ec2553890ec29766bac7e697c5ea1d40118be2372a57ad6b07511fe337ac6125fd8ca9fe1f3b691d715f2a212" },
                { "sk", "8b327db84cc18458189dfb43017ef91bf64a8032c46df1e0bda093ae5f4b4b36d2a2df04b6cb496088f43ad06d0e44e49205d900998115df158eb933c6af5e75" },
                { "skr", "e660548dbf58377c716e53ebf95d85cf6d7837b03a77bb3874061eaf31bc34a5138fbd15a9514ebb24043be6632b911115aafc189600ae83e11512f985ef4f7c" },
                { "sl", "04d80a6bf35a5097a5919ac7a548744701c8d43c693203a377b62b85e9ba8526fac5a59d51c94793d2feb588cb3ca4289163f4dc532794b223869692d35ab6af" },
                { "son", "8ce33da187f7bc12aa573dbeefcdd06f9472fe168131ff27168c99d801daa307eef04b9a749b8247ffd06b6b965a072ade3bb7091bd280ac622181cd9d190f15" },
                { "sq", "328faa7490b889459ca177514c92ad11015759ca000d60aeb065f0f0c477ed9db36e88522dca03dea13e65666be3f0c2d5f78f57b3572b8afe8fcc36a6ce81d8" },
                { "sr", "90881d9194d667c34eaa6a7801004ac8cda66f4a858d5df2d59d2e19b3372992abfb8e0544041795800f0e6ca388de5a4e98f09134d4861e221e74136041e6b1" },
                { "sv-SE", "28dc9ff1ee59ab09f97122bef28359763dced31f9379a522f2aaf8d2b9c99749a737cb5ce51a0719485bc3f8f0d8193a3b16badae86c413849f4500814ca3c6c" },
                { "szl", "6c313b8982be1c5dde2f91c9a7710fb0299561608c22ca4faa3b973ff94aaeef685094148cbc339cdee530bda736c3c119a11a6fc9e97cfa1154e8b358b97d7d" },
                { "ta", "f4f0f2eb5ecde83f71873b11c015559c12395042db5e704e70a591546aa931b5f052ede705008cc17389857b0fdf555fa0a63f9edc5fb6238894518d6aade225" },
                { "te", "691a281958ca7f8caaf096c3bf585ee4042f86964cad47ab5094781ba1d5ac191baa94ea31f760dafee220daabdb2e8c8bd25461a86afa4ea83b53f40fa4fc44" },
                { "tg", "380c3de8dcdabaebff133fbc45f010d3a458e13cf803f6d03386ecece45bde726e80a5fda4b23ba28530788166e8ab6de67d561fcf91b630ddc798534e19026e" },
                { "th", "fbea10a9d519db05c10e3d21f7e47771d9427b0f7c70561fbc5836e9546a002119818d88eb9c07340d0d6f96219d981346badea13a96df48bd98b7e4bc4390a9" },
                { "tl", "21d5410161cfce843928f96dcfd36904fe5682abb7577b8710aa5901e99221499b8838bd9c62c1831909fa1bebfa97082bd3e3c2a8cf87d26d0f2da4df8360e8" },
                { "tr", "d29ea116ea1ee6d11a803508f0863f4015984df6eefddb6548a400dec1de3d5e012f90cbd47a9bbdcc641a598b56984b84abf3ef68b3747d91b00eb08ff5eada" },
                { "trs", "b800fb0732fc6e50320a5bc8d3b646832ff791d3b15c9f0517da9a464032442120122191e5bf38da7d5cbbb1a4fa68fac202cfc4a1e48cac2ecbc762b6d7887a" },
                { "uk", "e653b5f215b2ba7f1073db60b2e41d7ad5deb0490bfd498bfb3fb15a9ffa2e32fbb831d00c98c301559018fda4885db45e33dc074b6b3328e2c46eaf5b1c7b12" },
                { "ur", "a86643a1e768b1762429664bcf4ff25186a8ab2f623e9e1b8f657b1bdd982e2610734ac9c2f4739b75c1f29c94ccd14c980d2560116e5f679e568a2cdc8f1a71" },
                { "uz", "081a464bb226b7374caa026bae4feb8ce0869c46acdaa1f3e19927d4a4fbdde179fe5c6d207cdbd360f7c8c02f25b9633dc86cc9e3919329f90b5e9bbf175b86" },
                { "vi", "57ba18b4e25a8308d152fa3a72b01c10a4891fc7fc5610df21baac1f8f6a78309aa9906a29f49571c4795511626532ff41d479eec2320e717db00bf4f27411ed" },
                { "xh", "3ac31a12c36d411c88b04baf102d5a3b0c8e188ae5bec2f48d34e7e2f6328f138577aa91e526ddf8b8e4c61baed16a614314237d0604a4ecbc9855b548474ce6" },
                { "zh-CN", "1ed2d31c87782fa13d14347cb8e1f4b46525d316dcdc77855d3e58c4bf05a6d817fb351c5552f7c4a6e413bda09c419113af314eae671ed61bd0044f73cae088" },
                { "zh-TW", "05e007ae705572e8e4a7be60bab6b18a467e5cf61147149a564edc8a4e11b2dc344751cbf76eff9b807530f7833ae8c4f74323095279bdcaa1194613de9d60c6" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/161.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "b4dfe3f232ea233a99a25c91d6f8af930f9aba7f2b006f4bee6db35c41d86513da726d18e5ca30d9c36b526e0e81c2cb9767d0413b37580867fc897f5bfd3f1d" },
                { "af", "f89bd54c9db94141d9af81e1c4dd18104a805876fa9d2bedf3c4472ca32c082f3b213b1fc3e732c53b23e0dae952fc989022c7bd74b03e94d9d98f944b42e60c" },
                { "an", "9b3223bb4159724e6452741f1ed0870abadcb78f2d9632ddddba5bfa900e486a9926f27cc333b04067227ad653365f4c733d5dddce19536edb6874cd0888bc2c" },
                { "ar", "d3a1e725effe73ba6daa09bd88bdf34b287220fb478f0bb0fdded75521b83a0d8a1187c188d4434fc15f9a6cd2799ae6aea553ffbcbe423af04bea233b672030" },
                { "ast", "4764e7eba4de25d682cbede137ddfcbe1dc885766d4ab89eb83ba96a9ba2957fcefaeb73fb6c70e7982c7395a7590a29a17a619785fab2b24023dc6ba0a87352" },
                { "az", "74c2056df1529e42f1393e481501d590ac83ef3451cfbbf28107162543288abe682c0def593df87fb07531a92b147be992d1c0ef63cef7be66e1bb803f9b2b52" },
                { "be", "9b6a35530ae70e3a45256ec2f65079b90f5640c75b9b936091722208dbc2e92b6c5321fa79b30cdf298b98ff827c35daefae944129654aa66deac73aaaaefd01" },
                { "bg", "d976370fdc9b993233a2f778393665cacfb4fec67bf53c3d98411707c7ad2de0407268dc499a2a8984cb06a261340fcd9752c0290be7d74ff6e86c22f6e0400b" },
                { "bn", "d3ca9bed6db23727ce64920ecbc777103337475ec90e74351e5a4a19b156fb91451b18eed6746851da6b493a25b160011374f36d5928ad98bda5426d5aa0c60b" },
                { "br", "58da94002f2efeb19a312767100ec75bb2b3655062de0ade63f0fe113af2af48766eee218f7129e662b5d660c819fdd2be8d6e4d37d97386228435060d3c9e9b" },
                { "bs", "eb1015e99c163d5f77c579febb6b6542b06dfe4cd1bd8134ba8e8def8488478fd5e861402ec538db69c4aaa22a6a48e490be2b608df035bf4d16c9ee90b5cb26" },
                { "ca", "15b5dcf04a87bf3accb3035fa3594f9528a3acf954a8bd9ca13fae8587cf1260ec0d50bf4f5c645a6dedd7e6a0c74f846598d89f3987b2f11c0ae420bc808f21" },
                { "cak", "3de557f670fe64eb31e7e4d6d87ae274072322c77ae2864e2a12e38bec14033a4f75dbff0956ea55318a9350e7fc0591878fedab834d9ad06cf598cd5f7245c9" },
                { "cs", "6d0c17780427355e15485c2b8a8d738ffe7f85d84a4897aac127afff2494bedfcd8b10823caf390b99f64d9fad9a10439202e4462a8e307aef1dd7df20ab0ddc" },
                { "cy", "2a254afaeb1dbc1ee4bf5a24d82837b96eac8daa408d497c740130cfebec388b7f710fa7f0b9697d0f86149f9cde60b9cef8d60f8798c2e2445eb3da470a09bf" },
                { "da", "5944b213967aba6802df8cc1e08d3a06aee0b0b1ceed11b4af4807715825a0daa0f8f7aaba1c2c1a3d2c4d0834576c1afdc1bb1b58722bee12c6ab971bc17aaf" },
                { "de", "c858a284a7b6c38307b5fb5b52ec7083ea80d7c3ea13f1855ad9e4c16073af4088650113f2b8d8348a8b58547a67bbe2336d6501c73c6bbc3c7c0c9a6d0cb02c" },
                { "dsb", "894f8df9997eb67badb95eb7bd7519c9943608533de8e62e8897d10076e96f9e1bb2dbf5935dd5989fca28c4c8eb456e24fbacf579c4829f8a956a08c1e22861" },
                { "el", "886b9dca286240e433fcce2448f5ae0e2f8aeb3175bf6408b2a69a24d54924ad56c0957bd4ac89bb2e56790f047322f76b514711a7751809855900f6efbc51c4" },
                { "en-CA", "4573e14fd1f6230a332097e0d5af3b3f3cf4af758012b1ef770946847ba9eddb6bb2a5a4e97a0ee5fb94cef196152baa2a0c94d96107a143dd3aea21eb896f09" },
                { "en-GB", "2029a5ee7357b6d980ee5b147d7ed9d85cae88f36a5a74f73cb1098d483ab0f93e6f3a9a572d3092eea93d7446a65fad1e964ae1eca288ef40e7d54a1962967f" },
                { "en-US", "39d71027ff2625a58cf88a7ae03ebf41e37612914637960dd3f1b2609a41465cfc46b1f0e2b23f0e420510a00a0f423e9ecde96060d359a075d5c7e7e574fc4d" },
                { "eo", "8c22b399022c85193fa1acf6a35aec9337ab5bc87a271b1e08e6dc80e19f4c92128d7b016232997de026383b68fc638e04cab0150b2fe105b7a38e2507098cdf" },
                { "es-AR", "07985c4dc8c93dc30d05a0f0a38397bdab167fde92b907402895088b8c67261f7624fc5c0fc23597ddee1ec4d3a70c0cfe48e8207771d8a16f3236121d94f2e4" },
                { "es-CL", "21abfb0ad0f0423d8e5898f170a9c1762b1223766b2f50d77cfd677f41d0e0e4e0dca1d000c1f283ca6d7d8e3046b746a566eeb840f35adde21e19236df182da" },
                { "es-ES", "475b09755225e2c4d1062b920627cfe68080e055fa2b953d9a2800ed105e1cf204436de245a313cde28dd8d54cf6edfa0d4d8b31e0ba49df744afb1083e056a6" },
                { "es-MX", "f6e84ea13585226c37558983360ddc524b274fa9cda76115d25818de1631758b1827a844e54529a355446e628f8934ecb08af3675db070ca23e86df797452f3e" },
                { "et", "05f002107f3188b4ff7b2318f7bdd0bfe6228f192558f259c933a9a4f686824d97bbda4d3971e959b0f0dbc1b8b4ddb375e0782cf14def3bc7c6387545d57e4f" },
                { "eu", "c49527fa8ba904c45eb9e69f7d44c1c915193aa2c4091764910c0aba0e8f02d558ff07cb40d5cec0d8caa4f819ef9f775ea500650312b8c401672a736b59a23a" },
                { "fa", "8766f81ed1862768f78dcd85bbc568b069195fd5c5e41cd233f5b9cbf0245fbb28adc16e6839f747bc75ba93b610f74832c145bd5fdfe2636b3ded4c983c7564" },
                { "ff", "7100d9954ba1e9ed81c891e324494d8844026b4f3151146f4c62c32c0fb49fc7f99cfd4e474f7979f42085b7ebe8cd2c2f99696344b5644f8a865b8eac83d7be" },
                { "fi", "a615dcea718c22e909ab92572258f3dbf2a8c0ff6ced8319abcb465bd69a09cb14947abc6082c3ccba88897797b6ece36a20077315aefa5723a8da0453760706" },
                { "fr", "eb33901568d3e725f3e4e7403d3460a3100142a4b60eb267a27564658eb7c67b0bca6a5bc47ee0b9b01ae9491bd8e13c2c8715a197dd1156bb842cf386d317aa" },
                { "fur", "49787dc385e86f035ab6946e314ad3327a3acc56b7ae774e5807d254e8a078282456b5bb5d4bfaa63f6284cfcfe32865a08fb232347c77422f96184a98674676" },
                { "fy-NL", "49f36bee4df43489e1202b02c63eafa232c8220f172860811a4aabd1b269498a8f0e6830eddded9ea3ad74d7b56175d2f0c9f005e0c23460b4314cdf48787a6f" },
                { "ga-IE", "887926adf0b84f42a00f1fbdd0105002eb023d6698a87dd8596bb0add5ffc9e19f98385e82a9e19540a721edbdbeeec3aadf12fcd3546663006f7cce8185b9e0" },
                { "gd", "45db79e84d0167090ff35b56a4a52bcf0afda7cf674be7d30a3fdba184fc4560fd8d89ac2443503203c95c6d9f8113538251c80f8a3e6fe8528e80cd5d429bfe" },
                { "gl", "46a9eaeef860d09ec65ad096b4052b3b437f039b201c55653e278827aac8573368377272c17e39d9a9006e110c60402de1725cf9680a652c8f49ef1896ca38b5" },
                { "gn", "e264c53de7ad63517a825d893c1fbce24a006beba24aa1c3b8955030a1fb0ffd6a19dde2aba4d79f44ec8a931727b967ce26db5580a2dda5dbcd617a76003d48" },
                { "gu-IN", "0fbf9fefcb0c82aa546954b43bb40b2e48bde80c5d158b0b1eefaff2972f13fbe63b0c5cd98f303ea0a30696799e2943e4bea9fb6627674b95953de29e5888c4" },
                { "he", "45d8728aa95f6d0c7bfd797bc25eebc022879b2a993667409bb906ec53900c6782985ee86f28ef3f0e9da5eea159d4a4a43e6d1680c1f01e03f9862bad2f801d" },
                { "hi-IN", "95c86262dc8518165a6916ea5ab6fb92837d30136f7092146b0858712657eaa39890949a04a377e7df21178790b687adae17e44c024255dbb3fb5fd2227fe8e5" },
                { "hr", "3ad78f21c881165e8796930fc9cdfd188b9cc2356be12e5f94f6ef9f0239abe027d9b015322bd7ab9dbeb510eb4aaa4a12372762e62b27bc5744efc5c968261c" },
                { "hsb", "615d47d22545efe7f7d7ce1dc7f5e232e1e246c2da26195c6348440e257332d05c37861fa6a5d36264b06469e31b067fca1968ad2be83ae1dedf5d5c2e3bce99" },
                { "hu", "9bb248d0851efc2570611c5eda71bb6a00bb089a66c9390f7a00b1ac8111a051bbb1f151f33248f8d85617059c2af06bb61d664938ab0a11eec3d3f85df87b0b" },
                { "hy-AM", "7e5aba045b2555fb4c51abeb197bb7da6d86b8cbdd9e10df2b7f8dcc17128ac0e5a6928f12684c6fd0dc70628fd48dae0c6f5f435060385159645402155c3194" },
                { "ia", "ab1e4c008c0f4709944bbe28b183b83f238662bc353b0d1705e8cc16583426ab64a0c149e288d62ef71bc9c9c5d1ff9913371367da7782b484ffd6c4df664b06" },
                { "id", "dbf870b273fac8ec0cf2a5dd4d0230821b0848605a21dc799e43cb6ef89b3c1fc661bfa87e54bd34de83c0785b60aa0339146b349c4d00732095a58e29494238" },
                { "is", "d783a88d5e86bc8e67f24ab8b63c178dd629bf5114000b423f7797afbde1f3118f1149ae1c1c3384235f015a2df76a7781792a56cf2e1b3d91d96a549faa10e9" },
                { "it", "6f681212dbe1c8bee7b264b79b092c235fa2de4bf51577baec1cfb1fdee8da35a5250172d5951a091cbb43e242f1f2379cdc7ad78d3168f502b1789d45930d18" },
                { "ja", "7397fc8dd4c6f51d97204600bfcb88b329c275cf8b3c0faa9d83b11dc71ac8485268406e3e14bf8f5bdb8cfabe987024d7cb0089576e0f71f4e84efbbd6f3666" },
                { "ka", "48161b750afbd884893b34a2b1052036e74a3bd8f0f840ba1f104408b52815f175c5a0cd466e208807a8cabfd471945705b738604ea8673bef28f0569d1525fe" },
                { "kab", "be107ff26e531386fc948efe23d66ebc45f86ecc30b34bf22a6837fd244ae691bf26ccdee7c06bd244fd99a90ec69f1a058aed168ef3b57d92abbeb7f8cbfabf" },
                { "kk", "cedded2c518ebcd4fb2626a97353a8939870c4041094241e513fcfe6070eb8b30f37282a07a79c905e4a2fb3255b75cfca5f095aa9180f856ad998a893dea078" },
                { "km", "cf4e5a92f8640dd5e3bb0e5778d552c3600444c9dc8d22045e34ab6278edcaf5238cfda0de0c05f0ba55b13d7530e5b28baa25201403a353c84dd10810ba2ffa" },
                { "kn", "02d789302e182945c2baa01b8c336b923c157436f3de52857da91f7509e3ec35c58aed7e5e87772ecd1a114c12b6b9d573c3026bb382e64858c1ee0fc97f139f" },
                { "ko", "aa53a2b5cb1db72d4f0561eb8e54a5efd03dae55d94fc4b782835ee9f1f62162486e3920f64bb543a44f56db463d1c26d717c292c18e7e906d50dbbeaed094d3" },
                { "lij", "80de48f9b024d4f38744c6bd5d8854901c0eaa90f77e5b8974c60b4e33ce20a0ad450075ae49f30654c361b66d6f78b4c95d97b79306f5063718deb8604116e4" },
                { "lt", "3d4a67e9c53931045f4d1f3266626f82db07b2a46adf496ba224b14c3af92f6e15834080632104d599ea85ef048d23949553769ea15bb7d19cf23279224f5674" },
                { "lv", "661d032cb8e0d419f706000c44d3965da381e9390b27c528df2fdbf9ee64987c705cc0b9b4164a9778066178d775f5f8629a36277a6c0a405acf938d25ff4b6d" },
                { "mk", "15becefa395c333c73dceda0bdda97aac7da946ebac386d47b5c06f96f0d837e1b1d8e04e608763f07bcbab05f89d9e644409b0219400e5b55b5b09b21b16a88" },
                { "mr", "312b3c2c87b164e2afeeec70e75f865e6abf560688762bb74b15bdeac759fab7fcb86a9a12703565a5c64940bdbe3cd539aba7d1c205566ac7b5a56e284f3990" },
                { "ms", "a04ccfb6949c90ef6b2af127a05612c831031af74258f5200f145dcc054e625c7a6e49a32919011b0b454e25bb9843cb3877868d9b56b7670b6cacdf5de69e90" },
                { "my", "6b0ad2bda520e712e227675eeb706f53a61dd92fd28dd4b86bb45c8ed7e91b218e1ebe1e011c0ccc5f47c64b1f8b01a7147f80521320226ba968b04dd6948c8c" },
                { "nb-NO", "cab23b4fe05b23772fd84ac76320c5e0c92b2f2e1ce0bd35e1dd4d8fe19d5d495dbab4c64da1622b16f69bc0ef1b5c4fabc4bf24b72366330b2d9dae5add2b8a" },
                { "ne-NP", "b2dc257af3e23d419ba6541b7b90a08b96a7e0a5bf17fdcfa426ce24889ca0082eedae344cf4f0ab5c3394392e7bf95f26b3ddf5dd824867136cccc2e4d64587" },
                { "nl", "79d4a90c02c51ab62ef422092562b50e8d2b43170435f3b28b8f1667956e1b9596efd4a40055e31bbe5a1f70cd37b74e1c7321f96d7b61272adb35c1b69c4dee" },
                { "nn-NO", "55641c7f1f6f5848710741683682f63dee243d6cfc8b48ae4872796ec7251a6f738606dad19d8264b5e0a1b494240b8b1cba34a05561cd3f65f80e00456baaab" },
                { "oc", "6f1f1a19b7d0bfc7248d6d65a6b9139dc268ada3f10a1bf042770c7d9f1afb3b7b2f91b655e3c5e36f1baf9d177cd496a14655a0f401bc02b9f47f720c605b5d" },
                { "pa-IN", "7c9b7820559edf713b8a9289f0dfb7386559da69f3a917fe4cba21397e0a82dcfeeddcffb87be96a0afc72b952e9f37c5c936b6ca3c6afde9b172232099dd864" },
                { "pl", "6ae134aefdbe1f7185723916d4e16ac459f34a337c32d1e33468d018c714c6bc385cf0e81706ef26a09c1d2fe7d89233428656bfcc3be5242ed15ab193417845" },
                { "pt-BR", "c6e58efe827e817be4c21bb885c1acd550d8e957b1309b5da6036d5ef540900b515db7f8272f9b2ee9a29a1eb011a3b516ec895c3e5aa2200c13ccf626e6caa0" },
                { "pt-PT", "86eb38c5a71a71c7a5088c62f1ef84e492029ec4d909343ffb72b4b973b65fbc9be36f7317cd7ae7ffcfeeaf3fe1f55f3dcb59040be875f8fa38c74822123f1c" },
                { "rm", "418c92f7981e8d49aae0e188341dadf84f613c174b2d197388e1648f111cb6f3ee5b5ed24c0de3fa4a6b5b60517e44d1a4845bca02fe002a91ed1493955815e0" },
                { "ro", "d8acc835f812fc3a790a5c3e3ebe82fff7b594f5a65b849ee1e100d01bb3a4ff3863c9722407a59b3fc8c7edea284ddd90b85422e9e50ed22808f7bada13146c" },
                { "ru", "1cd197cb36ddc73340c42ca1addbef833d4176aed7c85c77c63123e2664079d72eb7f4dfab728463d26856e8603e2d075ae7a84acd5dea252de02b3de388fa1f" },
                { "sat", "cf612a1286c2509643432e88301f0645f35c05d03ae8a5717a29999d61f1f9d93fb913d200ec5943db56e4579155692359569895fd3e2c952672e24f0d7c7608" },
                { "sc", "6b11eb5977a1fda94f28329f13af817e6c420435f7ad6da7d130809749ffda7482c7d0d33d8a4b01ff21ede9f5fdfa711fb715391e37f900a63d56b9919675c1" },
                { "sco", "d63eceabc535e97b7e9c8be50e0c831a78972c29741a513f6c04cf95c59433f510706ab7c6ff1a22078b702059c3d11a6fc52e8080220b094bb47784e8059ff1" },
                { "si", "380c5f9d58c2a0712a3e1fe0c44d8033337f6b6fecc23abe8bc811a4b63b15d5f4c08d2d7a265f8aab3796c441a2c37614fedb8c1456676736a3094c022bdfb8" },
                { "sk", "24fc026d599616672654836f0a1a3ceeee304c441c5dbb53469085803e5f8b7080c87afa897a89eeb0eb809064fac4d2ba3fd22936237b7a5a816a78953e4428" },
                { "skr", "db6186f02a262732d10cb55cb4107d2ebdf4ddd5bbe2a330d18b93263cfd833d5dcd22b95b9443fbf8b41382b5b9494f851d66e0c782489a8b4708c64c81a371" },
                { "sl", "357432a62a63009eb6a4a30c802dfc7cf035e246dcf850aa8ef8de616b768e2cb750b64f8b6c4f2f7fa593d6bab6e1e11f2f11802a2f401bb121d8623baa9fa4" },
                { "son", "3fcd95bd1be00d414abf7c7c1807953f2b782d44f9ace45a48d99983cb92b3bca6db3e02b53790ba29c46094cbd1e649fb0b94d499f3f560cd3cd511eaf7a6e7" },
                { "sq", "af809777a5d319d5e8c1b3561a79136edce8b2e4de522eeeb1959cc3edcba4e4b1cd4e9f7e867f25731bb31dbdb21e1cd8f1515d76b611a3b8855b5b2ddcb766" },
                { "sr", "2943da0406f33c41ef9060eefa8609a7767f51298e4ef0145992a0b32c7a61d429bf0c1fefa85081a473ee901e25d491501e0f5710fdd97a32456167c2a91026" },
                { "sv-SE", "d23215f974a7117989c8b85811201dd7e277b14f2cdd44f773ee38065e32d093c3431a3ab1ffa3b3fbe54c3dd0e18bae00ef012fa5bc659adda9eef945ee1103" },
                { "szl", "2c6142638f478214de53ad4c6259e7c9aa5d7e4e603bbeea29a17c2dfd91f67e9c387a02cdc086fcbe2e656971f476e3eb76adafeeaf5b4fd0be4d17c9a7263c" },
                { "ta", "941e6c5d26144b843b70d1f2242c348ad1472d962037d6758dead71a96d8064ae632b5155041901416a5f28347629168b22b4030631531ad54d0d28428e5c6b2" },
                { "te", "ed199178b4f0db0b1ff66e3603b7bdd3aab1f776b683d5e0026dde10d759accac7fde873220477a36e64f48853c86f55f903684934564c58f6049793c5fe7b9a" },
                { "tg", "d38c49e286c1686dbac2aba5a7f2fbad905a46e09412101808a76b2ca6ad4aa4480c4c0da7cebb3caba0bd91a75e95001dce214915158d0e9689db55dd9534fc" },
                { "th", "64a05889c7117b77ab23529fb5c5da342063daf036262628b0e8ab61ad1c4f4668f7973289333ac4c481c3943d516e58d35ae77d556968d49b6e5b8c5a5ea015" },
                { "tl", "238236362d57f8c2d96fdd8a7ad328c7f7189e909937cd422f3e6fc61a65cefa0dea660d4ce7b330bc135d19da981a04f37b632b4a5a1ff2ed97e365e6c4644c" },
                { "tr", "e70f7698db61192844cf2597e90dc1bd0b53aaec46ed84eb193a47c634aebba54f22eac8228ec5ba188224a690f7fb3eedd7b476b7c620681221c18d1b4ab3d8" },
                { "trs", "c8ff076e77e37627a6c14e38aa2cea004925267f845d1dd188f2f621f0f673d7a7b0f4f37a2547b2f09323e87859002b3a36d69bc4388f22151e629ee4f458ed" },
                { "uk", "62b20c42757e9b03f8e6b71cb0231ae8cbecddd39021979bc9b3ebda8f6d98f813738b618e1aa445b3b5b8b8c59b4ab36cb48ae576e11c592ecfb5f4e664d36f" },
                { "ur", "066072fa01ee83b74fc3745bb9a557b2188a6a4ab43f4aebe5ceab2f211aa8c4a47d470c0cbd3c784265c7fbe31ac2a1e6274dd1731f793ba9c94fc08d1b18de" },
                { "uz", "a3a3f1d641afc44be779dad84a5192a5cce41f786f0aed5a3af0333197f8c0a74523603b1189fc0cbac9c835c16cd9a593df4e52f4f024494f9df68fa3ab6034" },
                { "vi", "eca099ca3a785a107968c5cc1b6d74092d4adb7687f2a496915440fefa29966579fde85be2eeb1109708c8db57cfb5da10701af7d7d3958661d48beec22292b8" },
                { "xh", "277540f93e74714fc4f2e0c54158c42ab15958b4a6938dbcce49c6c10baafecf7d72586a06fae777d733d3ab9d8ad821982316ea630382849ce89a30a152a22e" },
                { "zh-CN", "d442c5a7c3398a9f435c7a2788e128c1d68f150c795511d4baea81b5a8049101ce25572bafb5526daa2382584efe3c6ea7be7ca9eb0bf560ba53a43f780d09ef" },
                { "zh-TW", "b03eb2ad02c62668acf8bf2c4c0a058afbf63de4f043fc75fac6ea8612510d4ecd1c6914bb6b2a9ff2e1f4977d051b5f7da6cdab3bdd85ed945f2f79cf0622d3" }
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
            const string knownVersion = "161.0";
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
