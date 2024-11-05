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
        private const string currentVersion = "133.0b4";


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
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "dd45818be7cd7842288b9af354f7fb8b433995d637013a76f17f600ffeb8a88ade02f47256c0c8c851fbee6d8596493fd10958d2c1f8133e06b63ff59b734e0f" },
                { "af", "90e4328f1d2cf0e78a85eca243552f1139cc4ea69e31c36697043f5ebe99eb15e9b970dae8614489a2d363b7d8c44fa51c671ea501b294a66c0ff7477ff47827" },
                { "an", "b7a71be204be6fc9a3cbbc80a14c704c57e5b1394afe450672f24a2cdb18546e36f8d677e5b473aaeffc95ba326560a285509eb29b70b1ddae23d9704fab30a1" },
                { "ar", "43f19dd3893252c0e6f6d8888430503d43a6b7a756167afa906a2f3a57234ea28e141ebebf0ad960fe98d3ad71551750ad94c568501d6296fa6355449127d53e" },
                { "ast", "f80a0fa6aa2223c1ef70888bdeb2dfe91e4dbd201786f72ead2fb202e647db65e299d3f1e0a043d25f8e343dc5d0bb2d929b4a5def9fa4dbc55a7bdde8e22fc9" },
                { "az", "c66c8a15df073f0d2cc9b7456664a2be763c50eaa8fed7c082890d19e3c80b105c78393e28a590990bbd45a045af7933dc1cfc6c1dcf984cfdfe2a85f545482b" },
                { "be", "3e21a4b2b6759a51e14de65ec30d587e68841a164fedcdb2eeb56edc379afe0780a228be4cec96b3335eee8ec282bdf46579c1ce16e30e67056331c8b40ddc00" },
                { "bg", "35fa5461d5bda6ddbbae56700a2b1a96403b581cdc3aeb463ce1387508310875d88f615e56103983baaa8c1f28402d06b4557bc6483a9c65846eaeebd99d17d3" },
                { "bn", "f981f13c9f676dc71ee18fdc641903315933cf836283c7bff815cbea08dc66f52e7fa6e20b467d216b61279d5220dea7368d799de937a0c3fe0e8495b8d5733e" },
                { "br", "88e1cacd51b8de65a03db438e19747f07ce4cdedd14036f3b0dd544f201928c5adec427882c304d9c3efa2c27a1926f5caa9f4cd234d52fe517b9f7aa83c45a0" },
                { "bs", "712a799e0bc6c3fec6e138e3df676f0cb84157f6dda0363db2162d3fe9b99150a76c400f726bac89a73de1d0699132a9eb7bea2cca838cbe48ab1594f597086d" },
                { "ca", "229ca78b78dbdc19f47ab062a6629dfb72d7bc197da970b05d99fc2e85966c609ef1665d64b09d1d19ca8c9cf619da0ee759d0fb6914d1c6f82a655c9bce0377" },
                { "cak", "b5087db36110fa8a4cddea38892826c1529e54fff5f1e66874657bdb64dc82cd3c70b75ffcf546af49e33738bafeca20a11e8a884a39501ddcceabc899686a6d" },
                { "cs", "984d6f6fb3e74d0a5f771948ae7a192a120d6ac533f94953f4a261c4a8b30389df462f5f4e6e99843cfb8bdf9df6b10a8af3269de4909f86b492400b2b0e312b" },
                { "cy", "9b41c7ad0cfff76fa1c605b18b44a319a453b66ae03fcd41510541a57d12d6867357d77353a9229330c4063c2401463d8161bf081413c525e5e0bf35c66f2442" },
                { "da", "4670409a49635e76528bd4f78609834b2a2ec88d01929477dbcb22692a45483971a3cb15633f802602c09028f4d3af84d5331554531b59b6f02b4cc9cc5ceb91" },
                { "de", "00808439b5ac05954f5665b30c16f12dfcf05a1d31aa343bb2534698c1091ea2c7b787f387887f2887aaff3ca044bb2ee2e79608d59587cb0f797b04dbe604cf" },
                { "dsb", "b450ad72a700096985ed0b6392c6a4146ea2fcfe8599ac9a4569b4cbc697c8993491e94bd48f3177cc15883f16c045cc2473ac75e39dd8815fff6f7f893b8987" },
                { "el", "1e8fcdcc9ee2cb08e027aecb90b76d49dd0a9ab2beb27f17e4bb9b1b849fde9aeb8f2c7528573f7d1d85d78776bf119be1ea566a545a2b0d9e790e5528941ef8" },
                { "en-CA", "08bd0975ba0220f06e5bba3d305b45b7329edbbb748e38844e6223f825e0ab080bb2535830e3b68c7d3c47f974956212433de0ec3bd13c888b0c1ca80862f135" },
                { "en-GB", "556504bf2caf5813477857673fff55d8bad8de64252509559f6ffc5063e3127d0685abed6d4a4dbf515b9fe4992ec1453f00b9d86ed5fdd4d7a1d828526225ae" },
                { "en-US", "88b9c32c0ddbddfbe3fed7503355294fc29e63fe9cf2c7db22560dad6d26cc72575940261ae5eea67f48ceaf83ada96ef13a28a022ceb04c0e8471cfbb7c93ea" },
                { "eo", "2158aa9eab63c8be8a303cb37f7f332fc712440cda9b6e3367eb25f337e143256aafa19c6e6778d9059be22ff223dc921579ebee33cd1d456ef21e657a4dd249" },
                { "es-AR", "d89adc70955069e92455720e885f5dc54a8af47aaf35082156545bb66e67f23f3fb566dfb9077889535d0cc14394592d183656f7d65b9953855c7c41855a8600" },
                { "es-CL", "ec3d861bd7186b9fa3e725589f3ee8a1e16e6fab5f70163eba45fdd391ebfda85e2518adace5c062316b9c20b8b9f7436fe5d40d07df278e035830c857927d08" },
                { "es-ES", "ec2c6885057161db745cdcaaae60f66fa40798fbd30542e2fbdd8a9a2e8f0edff7de204678eca628a6d3b9bf672d3795e031b3cb27688be7da632f1833e035b9" },
                { "es-MX", "023f7a3923380c148ec869ce4d35b3a29aa0bad68e395689bedca44089d87fa3a72bacf374c8e88ea71c567b3a2f4273b361e227725be425f7c3f41db90ce659" },
                { "et", "1b5c510eb29f70574459cfc253a39a1bc1aa7b0a754ff68dd3dc88849c0a5731e1937c0420ef45f675ec7400d7b6f1afe1d41657a6b307ce7a5603c49c9fef37" },
                { "eu", "ca021ed6bffd497154b52f24341910a78b34411cddf6a6b850fcffebc8d86aaffb9818f12dfd2ccc3a1f7fb86b63add8fb636f1318b02193f8dd9439cd19fbf0" },
                { "fa", "3fa6a4da84415d8571852ee27b9b64d35e4fc933b9292b5713b224a31378c2a3525167c75da1106381e52ca9cd9ce1a4b07e3e70dc7ac0d5b45913abd6bf3451" },
                { "ff", "1b7c016b7dfef1e042c8b8b5aa4227fcc1bd47f53aa54ef8a66abeea5ac25c94b94a277f94d1ffeabc726404ab1afdab91047b4fc7a58bb7619296027afa83e4" },
                { "fi", "0e056718d103f11ca34df635840871173caa5a8bc0e2e203d5c706ab4d279eaedb9a988d5d06fe46bde551e6a52a02fb583f7a4440bf059163cf95706e7d9752" },
                { "fr", "c4f1e8f4795da301060598cfd3969cacb7ee98f695e84102c1b2a2df2daacd146a39880ee62b293dcc31a676cc0a2c912cb7c5672b4ac118fc62e08b3238ba55" },
                { "fur", "605b9ae0e94df36260903284ed03f9a75e72088228e65deed6c078b24e21cb9f058df4d4886800050b84ec7a7d80b1c8e31aa2d827e2f8107c9d79abb625c11d" },
                { "fy-NL", "e52e0e0505a71522ea76b5ebba21f4c376aeac06ab51cb55243ef65b7cec45aa78598870dee8cf14fbccf564f7e4c321ea2e99c059df6b5361b7aafe4917be4b" },
                { "ga-IE", "4c87ee92b139041a070f3e26067157d8edfe462fcd5e45b785dd415d8b2ca2ed07f9f5a31c3bcacf714f0761908e4d0c0cd072309f6af8bb160c3a59595501fa" },
                { "gd", "d6f6dbf319316d0bcf71c711133e6fc320010483982ff5bc12668721fd308dbc6d6c106b4bf2933a447eefd3e3975b2f479eae06b735f6e34757fd9fa8c84766" },
                { "gl", "0dff36284082b9f31af9cbb45f07590f72c8467949c84dc891290b85d4b2272ed190176380043ee8f97a1e241a995398505822f6eeeb39c5bea0c617289da2ac" },
                { "gn", "81bfa5f9aff99e23b650bd18c972903d8f588b46c5cfd638c3e3942cd6636cc59057ae567ac91c023e444cf4cea2779241901c8462708e33e9d30f7fa4759f7d" },
                { "gu-IN", "7cdbfc1e30127ea28c116045e5d7c348a8a18466ab62010eb9b8643c3c1f5b2a88059d9f0e9ca8a95f7c58011690caf748e0f4701b2e004ea3c99fb71de69d32" },
                { "he", "dae3d3cf1cdeb8537064c79e059450ca46fe001f6a4884ccec0ede6df62ae671b2a657b772bd692957bf0b4266759334516914f1320836c4b2bd701115955b7a" },
                { "hi-IN", "107ed8bf4974a8bc6a33e771b9386f905588e7e3aa189a9c63867c9e1c01806e0c8619690f5cce77576dc5d837de9d79729a12fb9ff2651dcafb7754a1971253" },
                { "hr", "b83eb002a5df03cac0084bb8ee2b3d9ce5c13646eadfdde51e5e86d035686998d678130b84a3f77d94750a48fb47a36f06579017d36aaf9a176b73da90790360" },
                { "hsb", "8569db671c7221e7fef6644ee66b7393179566e3f9d78804440335b13b7adfc92870735437fd6e7e82dd37d71e1c9871d6bf3770c7369822adcf00680b2701e2" },
                { "hu", "8818cfd856c4dd6c594315a8bcf0df239838a5e5dfc19524aab6ab2c1e867d1151e456a3778eb3576c4245ee79d869301c9f14082b77106780d19892a2edfd84" },
                { "hy-AM", "2b7b42d0b72d4c8a29338c4a7c09440b3cd751459d583e105f24989811d054937dc4b88f141e97bf1f392c645ad9016746c44f8294ad59b1863a338b1ef975b8" },
                { "ia", "f7e7b458078ace43f1d10f053117333470c11c55589ec7d1ee4ea73f615b646267410fb497769b02c4e68e0a317b13265348381818970038b39d6ae92b647a28" },
                { "id", "7795248e36bc6138f48cf1df4ecf238ccff55b1d3abb9aba742322f584e077184b6627bf6907c54b4d140497e5389e10acd7cfc68a42b899ef9d4580d71ff2eb" },
                { "is", "59c828daa02217981df9e07c403ce4ea04d50463cdd60587b5ce855a45209e56f1c37c62fdc2349379a084160c7ed0bf55bc6cf837e1d71dfde6041d8a616cd9" },
                { "it", "328a9a6f3d0646afca839c33726afe8c54d8aef853d230af374f982bce927f48f7a573712e716b0f08fd8d9c15135a07afb286244c45476030b4dac7cfea2858" },
                { "ja", "e451b3fd324f5970186279a8b4b0f15715a0f18f2bfb6d5a549a98943e684fda3169a7aca8aeace788bfaf7aba1c50fe2a091aa332380b0ff40011fb48cab125" },
                { "ka", "22a584014edd1bb894064f44690529dc842105184a841c46fa1705a8fb19d02894d055e1335e795af13f7925072718aaff42a1e1aa3bf97f577d7b5e4ccf0c97" },
                { "kab", "f65b5c0304b689773cf4bb2e7a8cb85fb2d86ac9afec59c6a6db47a1d5827527590a541fc5db90622884d2c7078cdbfbe5c91c0ab5ca991e7a50728cd4081c4d" },
                { "kk", "e1fdf9667940955c3cae53992985882666a25804aa3843970644383e6a98b405c814601dad67683f2f327f59e4003ca1f150410793ac79de5dd0b635431c274b" },
                { "km", "7422c8a49771c756cbbcd05f69160fc098aa68d2008e116e958ddaf83f544cc0ee1ee5a178963d7866896663ae11b3cb1cb80ee6d2c4422c7451a05d93fce274" },
                { "kn", "932527dae69dc98286f55dc73ec1ec6de2eb6a7906d42d77ca950377bd1a1fc63649afe71096aa8cded135983bf721ac8b678975a5caf1c04a9bd418fe0effa5" },
                { "ko", "66ab666ac547035737ac4046131a58448c0f4a59ec519a298c8313b552f737f4948a50d9f00ac71e7724a91a378bd172151a726110b4340ec0cb5f95d9c09735" },
                { "lij", "da72663f929c4a02e43253363e38afd378a7432237403132f153f5d69c99e6fbcbc9ca3da25100e4540d09ff0bb5acd09d6d419dda1558b339e25d13193785f8" },
                { "lt", "e1aab0c0427e710fc0af9b689b289a2e8d1ac4af7e8ecaa3f90b5b44614738471792483b09a1a5896b0fb375aeee7fac6d15c2b488dc2005c5f0cda473bf12b3" },
                { "lv", "061474f0dce1c6ed22cfb54ad64e0bbca7e6edd0501c84b4596fbda537459c274bb18476eac42e26c4e8447a3403e7c8648e771bf190eb0f9e5fbe6025dfc2ec" },
                { "mk", "1ddabd603c4ccdf5ae4cc1eef0e6e1056860e0ae070932f001c53c63679a18a6e83b1d9e0c2ffb99548d729102a39270f6a9e74803a9b302d7c25ed75a2175f5" },
                { "mr", "00e74e6cb63d4a811ee58d37549dc63b64ed57cd57579bddd29002d8dcd243a5f94d7aed58aa4aab4135935748eaf2bac6c3dfa4f760a92bc011c795b102be70" },
                { "ms", "5341e11f6dd2791ad79cb1a98fe2c7e822c2feddf916f270168a5586c37d827d2c28419b828bd549fdefedba9600c60d2e78bc0d8b71653d4d33da95a0142521" },
                { "my", "63cef58c7c72f149a503088805c18a5047065a7742a7ecd1a65cb7b5a627d4b77c5317fcd071edd311f250d49f1eaac56098ed657e2e3038459310aaef473d96" },
                { "nb-NO", "3c200fd6808be69d63f5de50861eee5c8b48624e2d67ae97852077a82a8acc4ac0f2f1fd0feeaf7ac27e06101911050ef7cdf542fcfd98400f01b9276cff6cd6" },
                { "ne-NP", "a12f40553bd9654defcb4d4d544ac8be923f055631883b7eac26c9c58b8b4831174e50d7fc659e6a90135e389da5c9e82de305bf8e9d742ebe235e9ed10bd164" },
                { "nl", "3916b517e093c97ab6cfb1ca99070a0487d17d0ae6d9f0f1462ca84699a19b3acf9072ae0223fe1ab4fb0b75b47a3772ba31922abff933b07e9331a531b07081" },
                { "nn-NO", "c611869a377c9442727adb886e9f8a339aed1e048be9c2cc391f9f93a09cfc5d271adf95353cb8e55018831a98018f07069b109cccafa34cd91bc9d3f69f6ade" },
                { "oc", "6a406da4b7c0f6ffb77c0e7b36aad40966591ccd175c6019170da30b41f3c0f5ee1e80a13704002617a1b03e6320e126718a3deeca44c9d8da305149d6c88af8" },
                { "pa-IN", "e01c241682d6dc333af26f93d93a4ef33f8c1f4057e8bd0fc6c2f5d5f76f2fb5e6e8bc8875e6f4e9d2a1d6b3ce68b5fabd4ffa0334d5c78d1aed2dca22e512b7" },
                { "pl", "b5b1e620c0445f7b70a1b6dceefa3db4134d8d81877d897c948dedac67a488b4edb44523e351828f57321ecfa59c4b180b1ed3a2cde4a608792840d4cd071ca3" },
                { "pt-BR", "79441915d641f46ff92fd991964cf34e05eb09bf7e5d67e491d459572fc884674b536b48e09644c317467fcd9e126545a2b1331afa0c7da2455ed183e256fa07" },
                { "pt-PT", "61d49a7a66e9f81d7972a8bef26e4720985c3d04ec4b5e9948fdc7a99bf005abad9145f59e8b095368eb7e44a6435632e3134a49717ff5c7fdcb46a8dd524d2e" },
                { "rm", "4ef86794a8416913e86c93956c6d5f28501934451c76fc66a8be8a762bd5906e15f1b09b13411bf8dfff13da6af67c09b67a4dfc07d1c2cf4839402ef1be0bee" },
                { "ro", "6e4e64bfabf1060814a995e39947708518660e945520ffc26318ed2e838e09b7362f54b74e0e43d8dd8bc89799b8afd5c7091d44187dfba96124cedff5d7d027" },
                { "ru", "6bc0d36e8b3e3d1e0722e47f20f9592b3655ee113c9bc422285c5381ae5038556d939c6628c004de6cb1460afe90e1ca41679de36c814d2b02acd47fc6539e91" },
                { "sat", "d98b1a31fb7a24467e508ea162a8672a04619658ed0a625281e8b75957e57d20df60e27644c353f339d74826a25d7512ac2fd9344a98b214f4bd7ff83fb15ea9" },
                { "sc", "73a3c079801217efadb52c0286a3674120ba343519d076c372594fb97d4c8a791e3240f34f65c4c08b30e7b44a193fe63ff14242212afbc17591d27cdaa7fbd2" },
                { "sco", "c6bbc32a2e5f23897a8d69160c90cb48f0ada25f760724e54e12257b1f37e40ff8994511295b8f0a55157d31ee8706e377d1fa69323abf928695fc6b0348e4f5" },
                { "si", "540ac936102f02dedf8813ae0de044d2d5b4b4b98acb4dd332fe810fa452f7aa6269c01ecba1e0bebc0f5f4597ad6aa4627b45d2666c4191d9c3364ba6f79a3c" },
                { "sk", "f43f55e5904b30f4e7b83308aff3218eca1b3287815efd9f51c0c3771e3e5de4253a9230267b1e985577c46dad8fa103c9abc001feb78dc671555e65aa1be6ea" },
                { "skr", "0660c32128c219aa5b79357c3b37f13e2d9c2e968ff90da67bdf2aac9a1f1db40fc474fe4bc769c72b1028a0f9578ab7c4796c70b557451202274fbe36aea6db" },
                { "sl", "2d67891445bd275bce8336bc6d7211bc2dc3dea0b1ee9b5354a1bf0eea7959934d3aa67fa976b9e1ddaae86a843b0c73616ccf9ff9debdf60a0faf081409badc" },
                { "son", "83042114c5bccdea822600df260ae4940e33d7eae44f4fc1a0f9d2cd207309ac6128602fae5fecc8423c16eab9cbf5a9b6b34a45dc52b3d55d6177de3a76f9bb" },
                { "sq", "b4c0200f9d3705ec917c0fc3650f1420c43afdbd63369f7d97a5c453a3f530943e445d054e09c939bbfb5e71b4d5a7fa3958ac452ba1826014a0574769ea95db" },
                { "sr", "5d689ff78dab2d001f42e7cc7fd424bd8c0cf78a626004b9cd047835918b1c3dbd46fc51fb18dd4800d09d79a41ba5eee745ddc48e5177bb9091ad0d7fb714d2" },
                { "sv-SE", "cce86999352113914bc6bdff1d03c718ad96a3a4607bd300ce917bd0941171d23253ae58a16c979925584030ccd7dde76fe569f4118949f21f09f53b70ec3924" },
                { "szl", "1c083370cc0e4c6a897e7203aec4fdf66d37552eaa9ee0b7e0906b9f2fbc57b357d98cd1519bee492ca9baececdb331fcac630eada6c6133ae6a18d794ee232a" },
                { "ta", "a7594017783bc69f44143c9e9cc13cddd60e6b8793d16622db9c04d04fbb2875be3239654ecc1dddd9a716f24fd38fc734d09d6e8b1ed07356dcc9c8a556108b" },
                { "te", "def23f6eb5e262abfdca6b945f38ef9e8fa8fc512d7b2f3ea4343f568202c73b786da4ac87309b65a8517daa9d6b0269c539b3faaa81c7fe416e52ec715b6887" },
                { "tg", "bf1dec7c40450844de5de6dc9fb174ec45dc9421e91b52423ff22ca57dd1a7b8589e802f4aa5875d434fce3c855c6bf602b486217c0e0517a1385ea44b437b80" },
                { "th", "dc95537953d121f12a534475c94c60e11076db7e932b7dfbcce9cc1b3fdadef1830d8acfc05cc9c5fbb2268f2e7f30bd469351b4670ed65c99ef26260270634e" },
                { "tl", "718a029b308489cfb641a4139ac6c4538cc64fe38ff7ee8a6b9bc1d75ca29abe26b13f442d73d4334dbb28151f0d0a39051c38cb8ba83c339c0e69f9e769edbe" },
                { "tr", "b932cd22fff7a6bcd067e3430423e7ad67146130d6047ae362cbb0076cc705e19ab7072c42a6722db158617ad7c134ece7637ac207c774272fe33f98721a3093" },
                { "trs", "fdec900ff590878b0b97625d545d45de16758d522e6d65e7ffe32289d3a151f9cac8153ed0477fc0155158eeeb5122cb4929af158aca0a615e69ea36fbd475d6" },
                { "uk", "87c8bebbe95a875a23486a2015574fbbab917f1b53312c425e6afbca9c87496b165cadc8e8c0508f7db75091057f4f4de6a3f326fb1c8626586a9f80cc8fa465" },
                { "ur", "b347ef88c2093a5884c2f78efa6ea0425e70b0d81aa0d8b60d4182f05d91d14abc68866859f13571e3f7b5cfab713ef830b8da74a9448b30e089a1377e95a448" },
                { "uz", "7d8754e2c47f19e00d84b37ba1c6a485312bf8bb74b9eb140cfc13fd74adff5340c4b332de09e8c0d12c89e7c58d819d6afcd97a2f4e7640716dc79e26318de6" },
                { "vi", "5c4dbfdb75dbb3750ca389fdb5ec54fe123fe727472daf718637ef892c3f7cc1caae0048c03157fb78a8d51e8ca03efb2f346b53efb5dfa18fe21597fa8a68bf" },
                { "xh", "2e665b2cfbf5b5013eee7ece5994622997a5897a5da063f5e6b14e0128d2a782749630d73e716fb29fa99cae95beda6b09850ac753893f9a651090b99b525640" },
                { "zh-CN", "334e4b2a95b0c0fadfd68cc0e58fcf980b83f46fd98612d46e88cdf15c8a58a95bf2f060b421f4a54293460cf8284d0f69b8d2d86e0462219b321a290780e79b" },
                { "zh-TW", "756a1c979e4d5f5ca9a6a45ade13d9b29dd8d2f3a6bbfe95a872781ddee1a302603069aee6c85f22bfaf9c01b126786e276068f53f13f43d8304c3ac62a501cf" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b4/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "3441ec8f30fef8e015eab232578296d176eecb9e434c8ed3ddc901b391ef9dc9d78e98e9a4d18867b7beac9adc48d9ae07d5a5eeec210e70a72193c39656018c" },
                { "af", "a9dedbd5d0b37703b66d98294ba1ca35d42a4f046461493437bbbbe840ad3e6fa9947d96621223ec5f70d62b2b258d4efa272470d872f0501e87371b90ab870d" },
                { "an", "e10b3672575b6c45a9d22dfddb1e719d44224b1ee8bd0d979bb79684dd39de83fd52e38ea0eb3285d420aa0504e6fdb7f39239f613c3e6eee770ad76c67a1ed0" },
                { "ar", "1a5a8ff0b458ef0f9d7943e72084ef76ed9d8cb5dd8eda82abae5b0fe260cb372029b1cef028236475f42f3a2ecdf3b38497af644629ed7f7b80d8f761152972" },
                { "ast", "804590b7abab061fdf24593777986f9865d84f14d0ec7c9fe82d560f025e9930f7ffe5322429383fb2632c392a8c2f2953b1edd819771ef16ee3c2128ce25b1d" },
                { "az", "68831b3303fe64351c97c79dc917c290758b894d9538bc01fdb95fffd20f486b0e35de3a295c77e1b68c16fda359aa9561bb9306e8b9924fa404ba8ee2456740" },
                { "be", "f7498b0892d974b043611d898a75cfa43e161230f2124878a3141c56754e2f1e96d358f13860ad02938cfbb52352861f257b61040495c92c4e9ac69377438e5a" },
                { "bg", "6e26cf97998da7065fba27c8cbf423966e8bd71958bac0e0e1556a1d6fa9c4db6e405ecdd3e5af3866a4a4acb9b17a5c6067ba205743e98762e66b232954d039" },
                { "bn", "cfc77bbe41fb9bef75ae03f93924a951311121c8085559182896bdde682a15251ebfafdb0c8ff9606ce7be4af1eab7421164dbbd3ed0ff3af0f31e6436ebc76b" },
                { "br", "91c60b9c549138b5ea2b8622b4a37564761ecdd9ce016ade55ba0dd3c0a8e04cb17afe617879a9baa76d83c6c9aaaa40597857d804b435f10bf704b06065aa12" },
                { "bs", "acd3ae1920ae2e327737e85a75112d35d93562cd768b71a0e8e06f5d2b8e2956fbca097415a9faf20138e1674f2a9a12b492b190cc9b81302ed807316c26b4b6" },
                { "ca", "a3dee257d401634a4195022a1273ec7ff9289b9207627b1c51f0f9456a5e35653a267d909944bd939160f4dc49ecd5220e0fe053f08849b637ff55b6f6964193" },
                { "cak", "0eb7f65112273a77427abbf7cd3c52f1b5da74aebe89f7d95c6d274dfcc5191ddd9043cc59b2a4d908a7dc04dd4350eed6ddf37aaf98430f7ae881ad795bb657" },
                { "cs", "c6adf85a941060f45a6712eae2a63d1a931164d0f81c0bf79cdc81d50b18267de026bc3d3952b1c8fa843efabb1d8b2bea83a94edee78c45a88a7e09e178c0dd" },
                { "cy", "b4db539decd1ae869b11cba8f703349993a59d4930523573accb89c57c09590758e9da843950e2484a0de536ae659e4d061d923a2ed6f889b1f41247f50fc57f" },
                { "da", "746c9ba3baac3fe29e3f205d9b66c8e1f1cdd4190ad8c8dd1ab638402c9f27f8f2f9a24dcfc4ff10d518c827a4ae3075c4f524a4468ffc3974d9a015d59bd815" },
                { "de", "aa6833ace22bd090a8b7246bee00cbf4510d72c25a47865cb89126789657912c513876eb857b3f3df898caf43c6f43af46c25c1094e1432695bce14e9ba3109d" },
                { "dsb", "69e63bbe81545ad75ff5e95491e87aa6793add8e89d6dfa777fc4672a846aa01ff585f63d9899bad27f7d0b7424511a4337f2510a4c5fb582dd39182acdbf0fe" },
                { "el", "62b8d23a0afa5a363e8ddc0cd85fbe7cd4596f38ac02419d7c49f45b21b4b751ab3cbd9af3c509f2967424b191bb95139860f3febde571a52d11b41f1d942d8f" },
                { "en-CA", "ef8246d810af7d9d291663ce52fb872b0bca2f3accf4dbb61b29565c83c3adcbf691009b1b52dfb8422fcb57d94f5d961aec46d9cc0fd4f6c705ff7e99317c9f" },
                { "en-GB", "c20e7c2bf2f207b033f662ab93fc3327885d036372301d11a9113f14c843e0388262226a546b3011f138daadd6af3a394a27906fd6a0be8d5581470166f1dd37" },
                { "en-US", "c1ab1bc55cde0b576e18041e3c1dec42a3ed58e6688b88899160c0835b9df250a0464afc1c8aa624f091e07a6acbaaf586093b85244425f7e698e1f1e9d06d5d" },
                { "eo", "1f19a1635b31f3b9e19a2878dabba7aab7ff0b372550f5b42fdd112e8e1ed19c53aec5b01d5f53711527c2e4f80b2d28514bb425f6c9ed10f5badec3a1740555" },
                { "es-AR", "fc077a6f8c035c82bf8c4a597cf1d572c86dc13109319f05cccf3293e4184a314886936aa9c81b95b59132ba6124cdb91610a0fcec7dba1389c2802a50d95ab2" },
                { "es-CL", "1f44de4b5c32508489dbaa97ebc852c6c834d0d96afa0db77cb12bea4ad1c11945bf889c91e92c650197ed219767258303a9a4f6c7de28fe72af477d5910b0f2" },
                { "es-ES", "e100db33fa8aa7e38f212d02a22730650b6051c18c6fcbf668c4e7e57e504d25f7415500366d1301b992829d9035004753efd8d3c1d00283699e25f3b2d59b71" },
                { "es-MX", "ffc83e0d42b0fda65137459f7cd7d4a6ff0a4fe2902ec02829299a6b12ab0c1e797e6d2490def29d94ad515d5bd0b6031512093c16938688ef270df8eec82547" },
                { "et", "4bec825679d29b164cf0f485395b6ff343810187aceb6cd2fcc00db0c47b1a66a8bad575446d6670f37d395057886d6c19392b5a563500a5e1bc85c66e7d30fb" },
                { "eu", "a88cd420d1f97e52f73bf365a758fee8693a4a5c0036f0eaf93819fa8c141241b8e7d9812c9ad02f91bacf7b63b39792e8604171a3bc11e0be52e189d49ab203" },
                { "fa", "5583b2146b7d550e08cc6344773f180ab98db0411dddf55e6428626e4b783641d7dc155963db30fe38ef9342d850f0848db4e2049e817133f242ce243c1f3006" },
                { "ff", "df43346f04ffd7ac9958474c21cfffa8993c7de7302fd9df2538f5e41f2d504f01d88780a4571438d7f0e5e49abe2773dff67ef5168413154edb92be55041373" },
                { "fi", "a50d4f978364735aa672b1bd8cb45cccba9ea0f1d15e6c85be93ff3f081c878eb970d62afdb1f03a2daf6d5023c31b50c5600890d5fbc88f932788bb02c2d0c6" },
                { "fr", "ac84e33507fa4b28a14bfe9b918f8d0425b3aa39f0df48cfbb6556295d4ccbb58fa66a3329003134927abf62aa74e33389ae60e0de4c72cce07ac5f0eeabd4b7" },
                { "fur", "763cf3221cb8c46fc2966a87914b69701365c9e6f68fe8d7a4ec6110cb47d2478e8dc73e35aa61ef03605fa97d230d2988ee97e46555e4c2e397732a32e69057" },
                { "fy-NL", "252dc6412741d0f5079dbb67daa06c81adca2a59f22aff1816deb5f673fa1260fc95b474ea195aba3d84bd216234f1034b343d5dedb9b5b50292e4d3edaf9a10" },
                { "ga-IE", "28d77693a7d24b47f591350dbbba73147378dc03b5e41ed3ff2720e3e54c8d23acc5c05272015ff68e967a7fa3d1956f0d131641d78094d451e4f70e3544b7b8" },
                { "gd", "7ba47d7a71dc52d0c85f2bf8d6b8289c33271bb35ebfb5fe1b595a37a1c9aa2887ccd367b12d7752c9f3241e366aa0a818e4f449ff4c8330590fe3acfabad060" },
                { "gl", "823bbc0c418ddac3624ad7d67685774b9008a4d5f2113aadcacba885fd214ed15cf51dec7ff8a9225beadb1df1bfb5ff8f82b71555e6e0049b02f92ec0aa8f20" },
                { "gn", "6fdca292414655000c4afe086a36d90b1e449491e966406c15bd9803e8942b5df371d2aa1bcb38de7a78c9e528cdf8b0648e93d1ee2834fbd47e306f1379745a" },
                { "gu-IN", "1f720d6a674718fe5aebab02b40597b43faec3305e035ab9e7c7079bbab30ea78c01a4eb1a9585d2e1b3fc223e8412c38a5056040d4124e5d145b3951761b1e6" },
                { "he", "46de61c73648e7d97c59b52cc4b9045632e3ba29d437ccad295538eaaac363a22de79fa97909f118746b11c13eb1b6866808afc0fe754769dfedad7d554588b7" },
                { "hi-IN", "ea5a5b3c9795c6a77839a30e307f80ba5572d251c0db1b102ae2476375ceed55658d9aecac1d7b80c2094fc96cfd5986b1e9f8d44377293ae315e3bd53fe6696" },
                { "hr", "afd77c22c83ed095d4c850e1eeeb6334a4342aee05a44bbd65425f2fab397cf0f9489489153a93f0315780d3dedcc949861ccdc6b1ccb68bb3bc903d0ab73e2e" },
                { "hsb", "05d21f611faf5f612e7c5f4edb6851a9190117fdc8b95b5565a99e1fe48f64103dde6ecb097507625701b5218d8f0de2aecc145a51baacc2da42ee807b9dcfe0" },
                { "hu", "583ebfded6f6d160cdc2f222ac3724c3bb20480dcaebf02eb5a6d8f277eabb25ebc511e37073f037a989d5ca899c68659cab35733f3cc9c52e49b1ed688ef607" },
                { "hy-AM", "05f1a558134929d6256e82435c1afc4e010bdb814695fa08c25d911e57a15cc150f1527e8236b48bc75804009a255076d37510269d88b25c42195a43e671e7d4" },
                { "ia", "123979bd3023bacfc7171ab775fc4997649242bb6e46d8cfdf341534a1ebbf7a3897937fd4300dee4040d371589e189de5b1fe7d37e16b448fec3364098059fe" },
                { "id", "b9dab5f7c65cecf2f9fea52977785aa279e085e5ddc9a4c66695348ae8a1b2d5a3bb85f3adccf732ca134bcedaea2a8b933ca32cdc16922261f07a7e0c21f906" },
                { "is", "8593afd7853d8a23d3a2e60329c023ab2201ad20f50fbb4ce7836694de7439c2388ca397d75d1b72c10c55abc6c6d571e8919556c6f57d34413a7dda0e67ac7d" },
                { "it", "c7571ec157f4422334cf6e4c1ec2af9720c532f6890d9c6d2f6e8f388b99d081f6b1ca04524ef50708febb4fc3cc3c6e80dd2ce1b3864a1aaf5c606e7ceb0307" },
                { "ja", "6bdd4e848cd177a61451b0531a4bb7dac725cf250ca801159ef0f6980924a776327b080b1b71ce8b5e16406e1386814e54f14f752c2954df4039e480ee4c8926" },
                { "ka", "b4e73480191ff0655ee24dc84264b8388e7000998657ee0026fe9e8de94f20d4e31063f58fe930f8e2f8cc761982bf9ad8748c9106c99f18827ee58cae447f41" },
                { "kab", "9dc5157189ee72c9091d19dea1b70885222acd3c8be7933eef473e852ee65a1924378bfae51a5f51b9cd5c854e82f06ab65efa24aed7bbec7c0e30731128c61f" },
                { "kk", "ff91df83e5c477d5e58f5007323eb13db11c9b405151c8344931728375267ede3d492f13cf498ec6763213d7e0a738b3b75f116ce21c1ee1bfcd17628a298200" },
                { "km", "db204404a1ea968a576183bd8da0654429da818408a36d933eba55e6145d8b92fbe11c1b08d3c0e1d63ab16c2d7eabcacb74ec0363ba722102395b2d317fc84c" },
                { "kn", "754b29c3dd63f138525503ba34c694dc37937ec25d07a897d0d3adf19215c8aa73959699c424ad411eaef0d2a94effb627c030360ac1f6760ddb2c6b80b6c504" },
                { "ko", "871a4a074096afc1320f6711999e7ca165bf7a7bbb024fcdebbaf1aeb5d4da2503bb5eb52ace77d7aab7d69d3a1fa005794210edd93d75839123b4cdfbf4503d" },
                { "lij", "313fd593b58d29aa72e5cc0f1e45aea1cf4e0555a324a6951dfac1eed0b36354b161b6ba9bc65f5effd0cbf92e4a231d177277a4ea25b8efd7ee9ca401585b12" },
                { "lt", "44f244ad1d186afd79bd9918b63ab19deb1a9f996f4c7e86bb55e47c48589af844bae179b498a25380af4c0bc0cca40ecefafccfddcf3e4bff3ec9e3f931b9f3" },
                { "lv", "6d630b7c3f3370b76c4a8f957a34b8bd252212735ed1e5e02b4b0df712fee7274dfe33eb58a5a4afb869b9f091346a21a3c976c984f61e330fd007b632cac1d3" },
                { "mk", "3adf6609ee06e546f723c308d5ed5d55f5cec05263e8a0761058b9bcfdf96a472d315c08e0fed89b09436f646d49040652732715a9d84c3bbb86349013fa9f9d" },
                { "mr", "f0cb75e8e62569b55da02d1050db6fd85fa72801342d1edd9f15589fa5194f5e3c3309914ff4a3d646490edaedc8efe25276f24ba70935ce27989fda95538cda" },
                { "ms", "b8e40992dc499459dd1dafdd255b95cfb916e8a12398329cb884549dfdaad631c613b6d68e95689ad31bc4776c3195da29528da5413ca8a3fc2c12811622e859" },
                { "my", "067345acbc8f7afd0227a123adcf8dbfd27eeea00fc5dd3bce303cf54439786a8d646a97bdca00a9beb8c4336c695bbdfcc6581ba0c09ed0fc2d676afa94de87" },
                { "nb-NO", "5357546a8245aabc303bf09d0c976e11df22de579e5e6f4d34e0804005b0b359974fa954e5803b6bfeea15086df13f4a0dd0e040f07e49596d7bd7adc95567d5" },
                { "ne-NP", "99d5b060cd59ba25777ceb5a44824b71ea9d1820613e84739d8615118a885d70f46143d3e6b6bfabf5436b5687d04650c79e69f1091ab58010ad801433549d9f" },
                { "nl", "6ba428aecad645f671c0f8e20319c55396cdc295b88e44c657a310777933ae56584ed1ff1d56ce46b576bcfa70ddff6bf346026a85f09ce9f3b43a3a72b0a9b6" },
                { "nn-NO", "0165a7434c9bad4fe4d96b6ec4d5ae9a747f627ae6759e62d6609c8dcfc993be63a46b87d3875069a8d96ab3c278d45818b9cf984fce459f2376f887dafd6b4e" },
                { "oc", "e19ec41294c515c3516f7c1bab5b06edf4587901a25796867649e3786cb086e557e3983c3cf82a4a291971a05e6d3ed3e6afd9340b781e531dda410fa3504055" },
                { "pa-IN", "247bffc6b7cd7cb36549789f641ecff2566c9821f79b96ca012d03448e66e0d6b854153c8c7110c086beeb8b11584ff063e49e77a1eb33fb192205b9d789013d" },
                { "pl", "83ee679937b95ab9b1e7b4454d23d5b2c2f5e9f5347ae2a0a88f57312f85cb9d9adab6e8472c8a9355b83059eff96d3d546a01a2255f8b56579942666ee6ea68" },
                { "pt-BR", "dfbe4380fd0fa5f10804105c3cb9bdf3b78dec2e8d3e1d412234f922acea9d76b1a7d058a2e2a14260e672dc89d2553457a2f7bba2363da9d98ae3d09b86ea76" },
                { "pt-PT", "475680c0a77f5d45b22b107f61d90f043cc23c80f9618a4f99b425d0ec0cf88fbcf7f0c866a404299c0a86c10eb80b302a64931322cb00c1f3194f0afc9bd2d8" },
                { "rm", "d0353aaef3167d305d5af6019cc5e1ce1ebb86260215dd1669d1c7a14758c78cba009316396f749637cdaa3520ad04f62644fbd6290e025ce5ad585c4fa9fd93" },
                { "ro", "7599a72e1a8873564d38b82abcfb4ab77dcd019edaf264057f03f8a7d16b55669790afed0ba693c36cd6caff55926b23a09dd16ca87341c86e0ee534690c2ae6" },
                { "ru", "e8f6c3d212b2ffa30e96574adf4b8630929b35e5f13d5b13a83cd42c88e85963f41034651e6cafd1008c3761b39dc88898d4619c4da99bcebfc130d1ccaab3f6" },
                { "sat", "3afd53bec3e6f8ec08ce32801e5d392bbc9039b61dafa9be26cdb4725794f60fdfdc3dbe7f05684903a63e631df0a49a3f773993cd46e74e17f42d061fcfe735" },
                { "sc", "015b37f53b63d75d1338a6cd2db1736b7540203c4469a56aad7df4f3029c97d0a55a5183cc818df8658987c6181f78d6a574d25ea63ff4ed694fb961547efa84" },
                { "sco", "9d448f1576ff9eb7ef7a744dafd15691e8f8d8fcc18703a9f9a8cf0590a8c3a5a44fda44eb40e901ff35f9b47635e241194201711c47afb9347c421d150e2358" },
                { "si", "3b17dc6f19bebfcddb3b5e48107365c22926e5590db0bce8a5d3cb0024051aa7792959f8648416af50e9889a4c58c79ab44f2791436f441616f1f4a49c2aae9c" },
                { "sk", "0e919e1aea187a18865e8a064455f974c015d2c47630910d1212a35ab6c85c7e4cc055c4631b6879958b7db2e660e8cadfd7312c1a22edddf9ca8f21d8b376f4" },
                { "skr", "59341a836f9160f02028226ad8fbd0f742693fe9a254d2343282420af3b15fa9dca373afdeb1bf5b8ffeffa41320a06a08eedc26bdc096b8ab951f353c9b13d7" },
                { "sl", "e82d8e11b90791caf9f7e552e507fbb6d9ff936658b8547cd8af8b47801e52bc5ec0343354bfa4b79f301e9c24a1b13277de9cf596b5a9426e11ee3f37a22e0b" },
                { "son", "96205cb707bf57d878886e51ce202d03da2d28856b6cd57d9de2e366ab01fe0af6d4a0757abd1931765cc8d414b9d6b660e4c04c83d0141170e19fdb919fc428" },
                { "sq", "e167a1cde5f55db004e3661f981ae613a5ed728e0aa94d3710e86c5c1ff9eb200d8ac72f53c172ea9e61fe15c212c9c4bc67847ebbba267061c4b777fd4dc8d4" },
                { "sr", "57e68200023108269a24bb7ebb775bcc61c19b2a93e897b0374587165b346446ebd340fc95232003957c67099900074a8ed44682bf616303db8a6e1a4d0562ad" },
                { "sv-SE", "93c348432182dd1d5cfebeced6921947e1914bf75f32546cf3f4c31bca65f1278a30acf5af0a954daacfabeaf83fd2497d143fd37b55451ee0147f5da11b47d1" },
                { "szl", "36618065a3163a36ef5426d8282c3c35bbf9d2fdfba1f70bb8ab591133d21db2f762daec88adcf1ac26c5f0d2b30742ad9d0df2a7f7e90f8020e60074fc2a232" },
                { "ta", "b3ef99f0388674e7b0fa760bcd089bd3c700754438be03b059ffadafd12bd6eb8af1f2b0b7cd544117ddd188d59ee4fea96ba1ad78c6d562b8752e5df4501fbf" },
                { "te", "f2523778cf355e3cb264a7348efd84a1bdd2a748fc7a3bfbec461fca0c92e8594c20ccf7b52558c5c2d2393a7eb090b997a712cf06004dfd68a5524ef63f67a3" },
                { "tg", "69068787daea8738a67261b30d59292953c3b28c70f4d59655ec43d863002bca41011fd400d8dd17dff80fc934193c13d14da87927c35db7db98399d8d61a1bd" },
                { "th", "55ecf11292f73719a8f66b39362863ab996b505bd8a6774b5a6c503db6ab2af2e89c61b22e82384b559623ec8cd4bfffa5ff3bb9b99dba66411534a4138c35ff" },
                { "tl", "78c1766c73047572f94e25af1a08dcfc0aa5b3ad74091c32c100a39b73dd89c45de8ce85347cd9471512c6d5f33560a2fe95a5d8e34911a5b9b9722a2a69fab7" },
                { "tr", "bdc9e9c4824bc7cb364b94d448ce7559866569478a831dacbf34fe3aa282ebc764c298c2a4aaebf806aff53358556ce28fb8630dff328221a421ff42c95b6a5f" },
                { "trs", "ccedf25a82de7ea24f67f0d166bb1c2e1b7682cfe4ec6b66594cccaa0a717715737f6b29b62503742c27e5db5b3003c4020b8f0886141a5b89a8ff28eebff3f6" },
                { "uk", "cb29f277af42d3a2b6ea210b03773c6bd86de1843b09092bb66f70b5009dba869ab6acfe6ae23567ca763ea9ef26a0e0de5525b0342a7cefe07251e04303c0ed" },
                { "ur", "e7be353b45c5a490a9b5331b82a8984880c1fdf34cccd676f65eaa099a7668a9104b29a2c8d40b459940b9792998c9211817f1615052d1498b822b85b2ff2b3b" },
                { "uz", "9ff56ebc42335b9eff1f93971b764708e08cbe1cbacffbbb5ce9f50dfdafbf746b981a44e4c6e6d1b74f426acba2a3a966d0977ace33022d0fb8d9d6fe3e3a48" },
                { "vi", "7868758892a7f3976e48362b4f57606535d838ac1395bf0e484d2d8f7f1d78f0fd8708e65dd5fbd3233bc98fcc2a72ab701755a539f0271abd2bbac2e790a890" },
                { "xh", "a0606c0ffb86e4a15e25800aae201f704ec31a5d24f8bc2ed546ceec23a97ddae697483804115e1915d6e3f7381ee4f28da62b26cb28c1fbb3ebecc0b720cf0b" },
                { "zh-CN", "896942621a3e45563b5c5bb1bb4caeec4ce0a54583198d87ff293979c5cfc1467f1ae81f9734f53eb17309956aba82aef51762b718c0f9ac4056bfcbe836c758" },
                { "zh-TW", "b3ebddbefef2210acf7396e5bd7d0e449884ac062b587a24aaf060d8d2b88f0829f2a0fa4b7293b2de8ba225070e60651d290d0a036394cf78322f579670d519" }
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
                    // look for lines with language code and version for 32-bit
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
                    // look for line with the correct language code and version for 64-bit
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
            return new List<string>();
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
