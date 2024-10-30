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
        private const string currentVersion = "133.0b2";


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
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "dde36b755f3374362a299c13fb4bfbef2c4b489b428c9a5458ac8c5a2d2f1c72c7705f5e29503afac0ddb3863f3e0563c0ea856c1700a0f5a3ff8549cd461667" },
                { "af", "bc07c8d6278ce5f545ebedfeecffc2b81dccf5d5cb4fef81c0e2f257e49af7110894f3168fcb42fc5608c6aa16b2347834d23ad7496077a50372d1c1a6823c68" },
                { "an", "5315c71910f7f1bb00a1fdbca515286da4193a404f8796bf6a9e1adb703cebb0322516e1348434b15e866429f59560d29ed328e9252ef3ec80ae4fefd22eb905" },
                { "ar", "39f356cb3c035fa336d62db3e31b46b886df081692c693cd87c40100786e02450c54e660f76927b1db48e9d745da97e1b52504073bcb13d6fd7b2772eea0adf4" },
                { "ast", "94d7ed65583b35e1450f26f1100684b999b3519c2b2c8ce45fbe474dee5b19602b6ccdef0d068ab5e94382fbe37d92317b4d2aa0a0f51aadc8e179f54bd5a295" },
                { "az", "3625662edfbb6807e41c3a05588855058483f53857cf0f7d6553091c91942e2c82f02c71c7e1e37eb053275eb0fa67ae85aa2afabb8806872fc1a061c72d0d77" },
                { "be", "f16728957ab4f6b9656c271dc22a430eea336bfd006ea3c2fb5c73f1c75ba739c0679179e3a43a08a2f6b32ae049cdf7f5f33dead6bf77278251f600aec25683" },
                { "bg", "b340ca6ce1e4dfabebb41c529c52801eb8582a2f466b7148a45b1dc6bc50de05e2a1e9c4e703e0ee0ac1b6fa06aabe865cd6098f01b49a8e575fd1556e9968e9" },
                { "bn", "d65b812e53ba03a823516f12210783f2fae81d368b6e1ec653e5f29deb713b26c102035f1682a1bb8ddb130c5c8368d22a796d4472ba6c7bce848ce1f00b3e90" },
                { "br", "6bb1a8a69bf369d46b94bf3dc865361e4f45e95e2413e219b5dc73dd013b6772217b17ab0175da3eb8560965d790c43e5de7f28dcda45948585c550688103b11" },
                { "bs", "7362307b0945a1d6f3a3ac7dbec966f6fd1cbbd5f82600ac3148cafc5a3d55c3a60c72ecfafba71a6c356dbe9e0712f83d69f6784634f9640a4a6e3e1000bfd8" },
                { "ca", "10f69eee866d9cddf2bba683fe1978b6862600eb57c356bdd9a5bf7a4333c9b35525ce78d8f715c11b5db662d41fc8372de8f93916d5b40c34a58dea67a44219" },
                { "cak", "15a466a824eb4f6dff0cdd332271cbecb0e9d2a58fa8bf63002716a10b0be3610ed7ce9a3c913b33f6300e2de63c5b3615de0f4f24fc330e350cb8748e30073f" },
                { "cs", "765a7e8ea5d317b4b9b3c48d56caa030c98a9636ecffcc6db66c1b933564acb42eac2da4b5ccb99fc50721694eae88dcc345cf7c775a2476a60b2ab19e2aa04f" },
                { "cy", "a89f6c751ec1e973995c657f65aed5a27f03c64ae61aee0c5bac37d34f4a134e27f36538b40990a60f145cdb8684a30fd8c46a763be67ccbe797c8e2255d0e24" },
                { "da", "756f5c1db0a7179a27f7026ce4880d992baeb421beb4c2e78313f343706edf29134a55ab60cc8a0a139932e8384f37478874d915e792ab7900d3648f80198d92" },
                { "de", "fbb3c332417677728f0ef0db2adc4189c79d5b02c52b0f2c56d49fb52c351ccfbad1b7d3475891a1847e3fd8cf5348efb8917d32bf81c3e9c3618ac4428b072f" },
                { "dsb", "a84063a4d756b4d05f049043336c2fc45bb3ee3a9c9e4b1e229df9d8edfda05b157627eaf84fb0671d833da67023964b0a57d3f950d930abf71b9c491a7317cf" },
                { "el", "e8ed1ea036dfcd8841c7ee480bb233f57fece596a86499b465bea49e06078822ffdab1bb5f216ca7c6b5f3b781d8efc269e2a53343046545b09bd63d15dae99f" },
                { "en-CA", "f051d82ef8973f1234f65ebc5d010963871942b0acca50f24238431af8919940be8a9c103dc3c80e6e166224783b5ba426a74764e2fbc4526f7f7560d4549192" },
                { "en-GB", "770a08dcbb47ecca7e615951890d5643e751c56de919fcda6d2cd7c0fa117e90351b24eec6f8b337afe08e865b7c7e7ebdcecc34f0a770269835cfc3ff269045" },
                { "en-US", "23e9f482a3276bfad0d41223eb908d4598333b1acd8941d19ec00aa6c3275b3a40e78d6552a497b252f7e977384e22ba742e6dd3f3858bbd35f52585162b54e9" },
                { "eo", "09906931643414a295ff677a55e44149d1bcd32f2fb62a44528ec365aeb3f01371489b7387c71e3cf1d2a26970182c0c7d235d111d8e9e16f7a78ed4fac23e6d" },
                { "es-AR", "2f85b336ea36cbefdaa7d767da06bbec4bd2be1e19db48ee3e4576185745143cc02df0a61fe9b816ceb3b1a9e03b374588ac46e8a332d25ac0fde656bf078e69" },
                { "es-CL", "900eddd476e9b67da882f735c2ac9bddfa96484b64fabdf599d67bc595c50b1953ec6e42c3e36b99fa4195208fee6b8dcf6c1b9c96c88e153e488950df3fb571" },
                { "es-ES", "d2b2aa6c1a758c4eca8df60bde0b7ffa04071d6452a092b6212daf5abb5f82c5b2d3121757028a56a06ddef53bb7cc4089afa4bcbcc98b8a1275391c381b9d42" },
                { "es-MX", "7c8c493f5fc4fcb5f8157dd0e2a44c32d3364b42412a83d836abb12bfb7f967ac55ac91b5532bab33a482169f646ed90d0418e4a34786a83020b943ccbc11f27" },
                { "et", "8fc8c0d3de1a194eb339a2a4d248b3715e9061fb51b19da988a9524b29b62ede0aa283afac27a517a5f8ec6a117db8259047d7e4b6744aece33fb1e50cbd6830" },
                { "eu", "59c28a0c24716dd0d5cf6bad028b7aa86022740953ace20fd1def0029d7fa9ca8e2bb8560e9cd275793bdcaafc1516cc1343b6554a086c3dc0af0a967d6b9cd9" },
                { "fa", "df2390ffd475a244706b1ce314bdd7b59f0fdda5dc04f0d4a89d5f7d4cc12eecf7c009a0d4427f1d1f252920a2907389418335bb4cb772157f30b6657975f38e" },
                { "ff", "f1f151809171ed8a75f4b5f3d95659d0999f3ba2863156bf765623f3d3ca4fb22c3969cdcbcafed2ca66a4d3fa81c65f480d8f97256d51e3b6693b074a3041d5" },
                { "fi", "58bbfa1f215bdd59449b579ef87ef9184a48739528df45351fce9d9db04cde22f2047359be6257cff0a88f870262b5afd018d5debf8cc8bc7b7cdde2ba16ec84" },
                { "fr", "4e90d54c3036f1f638c8cef5657c255c108c420c24a567477b6b7e1b7afd563dc5566dc7aa73a7e00423bd0320e78305867e76355442e2a8fb5502b7a0e743fb" },
                { "fur", "0b8a14a43b6f1b69f4dfb06644a1efcefd90678aaeea268fd5e8069e72aa1b158dfb91e9e12e34f63ccc1d349d862f267c3acd3967c48f7f82a4657bea885a05" },
                { "fy-NL", "1753120d7ab32a6bd56260cfb0733c75ce152a60eed24153aac20b57549bc43e361e1b3986266c4b67874c8cee9995e28ae9db8eff7a7777d499735047932dd6" },
                { "ga-IE", "4fad2b12e507c288f3ffb829cfc8fbaeef91b3e7ee409783b2f9a276181479db9d1665ba13c80c479a1bd90ec79827a87f141845d2e660dfe0102c2f7f5e6e83" },
                { "gd", "a446a5c0fe18b6b990a867bfccc11f89460c8e41ca51f652e1843857f25940a83c53d1804c6b41de374117cc5df23e410f2715eaac071e4574517275e4fb56d6" },
                { "gl", "a26ab1d67f4f7e098d220a4f4992a2d7fc73bc5c45eb3cdceb767e99718bb72268538f74da93ca016a4c10355a0f07ec432313d63e5573ea56074d1296a6661f" },
                { "gn", "5b705ea6094ab534be8281788dc7a5de434a57a3dc98cea68681a95bcdf43a5162fe7d63ec2860eb2facecdae7ed6845e109ec31c8a6019ad68fbbb2d2ab2b26" },
                { "gu-IN", "2597d8655c8d904d13b76f519b629a55ca254256814a25a04ae8997b7283046df3b4faba592bd6c0544977028e84a041c7af41d4bbf82bea7cb90a39a1d0908c" },
                { "he", "5cab99727fd9c20ceed0ea510fecb1b205f82cb16b184c7361add7a6182a8043f88d1c672aa7c4bd46dec8fb82e3f5e0fe3fa7d7cfafc477c1dcc1e3511b9af6" },
                { "hi-IN", "f7f2b5f29a5c73d39f4ee1a05137eeaf39bf5f936cb143488e543a4a50ee149e9ffdb864bc24ab704e716e92dd48c745f842751132b8e491b9966c91a15dfc5f" },
                { "hr", "3572095d91627e5ed9577f66d1f3b66fe552378b26be438a84c408b484528e7b4f98986e5240a7cf0b827f3a9e4d5b8fc304de8abd56d6c4f1efd6b4dd569c6f" },
                { "hsb", "79f81b8836ac3b3695372ed59ef551c28f7a8a0de63d22c06bcced6c023365404c0af52c3580bfa7f887747a923690fd8bbeb089cb8694b434a1b45ad377d931" },
                { "hu", "e65d2300d8305e8f4b9e67b5d2f02118363198e694563ba5b80e88275f799feb584695ba94ac4f07f71a61ad63f31f74671764c3c740fa7bfce1df2ed4e01ab7" },
                { "hy-AM", "807d9808a5d1b3539b4734ed8cea1c29a1ef6f3604918a60e476a0958491c78a274b3d779ba122c50288303e7be66e37a22e478699975151e61237f4a6cb72ec" },
                { "ia", "df30194b78e45fdfff4378d3b533866fa74b9bd73ad93c2573b8effb72d8f9c69bceac52e2a43b56414ef00f100094cf87ffcb658d4fa15ccb81b4c84d7f3160" },
                { "id", "b096ff5d76a2ce5c084984723a955a04cf6a7a4c4323b33a3c6ca805267c52e79a827bfd4de1fe4a6992936ba44aed48449884772c30da820453501a96254261" },
                { "is", "fd6ab58e517d23eb89f5b1d42f9894e5ece21c93170bda555da22733fdbe60f74dc0c34ecc701c474bd43a8c8f0588b3aebd49ae762047314955a37375dc3dc0" },
                { "it", "370685dd2767fa278cbace40426ff6823ef2960a4354a5cd81e8b60a910698311bd623fb0b582b0a91913fb7ef77150b4a3393347c240d33dbe3b5736d57057d" },
                { "ja", "1af6cb845578764e3e6356738ebfdf399ca03877d4e87a04bcc0154a7aab6eeb976c98a60e172a1f2b3e30a649be2b8b735f21073fee7e57724574d5e6427a9c" },
                { "ka", "454fb5353e392af2aa9cd747ff27a38ebbd7b56b6f2f45dfd9fe793f17b9ab378418dc1369ccbb2f5397a9ad1b8da5839098d141e889382d5d54f998628d97e5" },
                { "kab", "173a270a3bc3008cfdbb91b944cb213a9aa2ae0c9578f135d00d83e12765adc1935fcaefa5e987068403d2fc59e843f5152efbe9c4a1df5589ebf11d8ffaffdf" },
                { "kk", "748a2d2f5f410df72c35ce2d478481cb7fa7915248a08e2f4cae55e899bce9399b8a9cc8943458a40fc78f1657d318ced00515c9d1c933191f26e0cb10f63ceb" },
                { "km", "a1d1cf22a4bf9d3f307095b66f699e853a3d5d82aaad5be49fd73dd898bf3abee6aeb0749d7fcd985fc4c7c102ab9c0e7a28f0e802df805594b4744656454083" },
                { "kn", "a73de7f14e816c3d14bc5dfa2d85db2e454455bf627a9921291977f0af550981d856c0f6c80fff969380e7ebc727f4935f3217da0b8bfd55932fb8b64f7f37a5" },
                { "ko", "0048eabe526c9dce14e00d3e624dfbcdeccf840afdeb64042a27e4a9d23dd601fa98c2db3e15f49c6ea71f177184813ef84ec305543cabf826eddd8a76df0626" },
                { "lij", "e5dd86ea3e107e37e4cf0568d493071e04eb54b0374bde2933d042c15034e39a6c5c07f34c428af6d5fa1c4a5a61328f86f6f9792907f6d566ecfde15e6d070d" },
                { "lt", "400f0f3e99c21d3e4ee18c13563cced070849aa4bfe40696042a2a0e168f63a4da425d28184ef158619e0b88bd213fa73770eecde8fab987f5c1bef5a0adb0ab" },
                { "lv", "ec6e8a16bc7a68bae3aa0954f48f64bac4eee367ff14d7437142438d1a60383fba738a3ffaf9840f8af9652f78cb64c992cbb00bdb935a058de3b2a54ebd196b" },
                { "mk", "6e88be3ca6d1f7c5a89e959c523ee4307ef2c0aee50961508400afa7560ac63ad65cf7b396ad1a8f67014a98c3b699ec2ee09c00a32c378065843165364aeb08" },
                { "mr", "78d770ad5795624b5e134c85667cce48febc77baacdd1be0ae1761c883b3784904b22b6ea416aabf657fdc71cdd92fdd944e2ca4a67a80bb61c0ffd36eed2c18" },
                { "ms", "9ff3731e39f6f3d73de80aeca044de9e17f9b9075e8c7f86751b2e2d108270f6614fe5c8dfae523d40549a8495728c1f93b46bd6384b15104d01f3174f8daef5" },
                { "my", "e3bda2325b7b0eea6449d81556924501cead92e310b4976b17f948e7a1f17ee7a57f99ea5e314b450f81a1660bde1b87c6c99e4cb7d2e0c619159ca86668b6d2" },
                { "nb-NO", "20f596ef24f2978ede7d39e79deee5e94e962272891d95c8db95734386b8122c11650c831d485cd671ab897b06655e046a03a1b16b107a68c6b5a5c7653d9fdd" },
                { "ne-NP", "4156c6b36e31e35ba884b071d4ff78e4f5316c6498629403a2f1ee2749b11857cf2a2281ccf2338796806a9bbae2e17710b419dece8be728f3e060912d84b17f" },
                { "nl", "803ade7a99df279cf6b6a0cf4b1ae5b98082dc41e6d8439018d2b60eae16f9880273e91c52fdfae7618004ac641a665fbe7fe6be31fe7c4cbf49f80f589297ea" },
                { "nn-NO", "165a32e51bdef2586acf7c5cee75fa5b7da818389c066f999438817e798c389912f299c13d801b4f37731ee6b09e71d10a112ef8428932610efd53bd0d22838f" },
                { "oc", "11e8befc00171fbfe1fcc66035cf248a464f10e8c8bcaa139d6ae43eb83bdebc546cf1b74d38b558e7ff5a9c0d8e4db76326fc8860f5b5c915e1f041319abc29" },
                { "pa-IN", "a41f3d4617724d691010444c552022c6e07d95560f9ca82a5d0180e39deb2e0500c55baea77d1a924619701e87393f39c4bebb14507751e64f76911aed592dac" },
                { "pl", "b37890379bdead4513ea7ac38206147f5415206cfc97a5ae3d607ebf5537ccb8ac23b27934a5a4ab2fa07402420bec8898b09c4392281144f363f71575be9516" },
                { "pt-BR", "852ea13a5cededb9f804b131bf81d990c501d64a7796b524abb54318d19d1f4304169ecfdcd8abb1cd8937c4051d6ed1259335b7a25dbd5d66f92541b0e10ba9" },
                { "pt-PT", "06cf9d876ce8e931a09a88ee39f91c806165cb4b06eec5e23e64c0217dc05e293a291d017780a1decd986b276a6a4802c44afb0d1b0fbbf1cca9822b1fa2c77b" },
                { "rm", "2352ad258fad9227a394f368063b20c3f175583bfd0c6fb12523b84dee41d80a647c4759bf8c9ff73f772e44fbd4010925029ea08f307a7345853d3e495761ee" },
                { "ro", "c52e74a331bbacdcc58210ac152a8c4fa4492aacd6b4f607fe155569c59d5c2cdc8ed69d7c41711d45984c39a8e28c49d7a3a0a8db724134d78e6b398beedee9" },
                { "ru", "b51d4256250c32a7e55b7c827be23361df48a3f520b9d4aed4eb1d1eb37c1adbaab137923273071edc6372682def3e5872ce726fa294adf17f75df272dc10c93" },
                { "sat", "20b47436d2cf90e1167b203282095dbe1f3de00787410e8b20b3dd8056179e88b999254608d03835debaf7f39bc2526c7498f3a78067f54e107f15721c24f749" },
                { "sc", "82f412f24921b5b9ed6432b93da58a1575f81e0f9b5a2c95c1b77730a3f23041f12f8c44f69e1305a02cc56a45b6b3b38954ed528fd5f0bacd29ca6dc4b60c55" },
                { "sco", "43d33ddd530316006dd856fc1898f334f0cb7188522072232d9271174e743c05c9637aea645c5a33c57be5f229ec36e259625432dd30f209b0c23191bb08cff0" },
                { "si", "da114024c3f655674cee9e6e7c831d2403c0e67115af57aff320784570ba28cb600e29a576e8ed7dcf48b55a3bc2aeb93fc2d31e2b5d0bd3b691af5076be560f" },
                { "sk", "da6c6ae97253809b39e72c661024f08f4bfae0c6f9b925a85bb850d981f3257d2f5d70dc5d7b954eee65abce7358f52d6e71af1e9c6fb17875afcf93567257fa" },
                { "skr", "d0618aecde8f87cdede4326bc11f29bcf856b1dad57150cfe9607ffdc35f659305145f4f198c89b32b863e602b4b6572370377677093360513839c36461a9244" },
                { "sl", "01ee91fba937062a6e7c28a5e065634b8e25951f420a1d69525b08b45e791f865f594464eb04a46af8d08e9acb2cabe673d5a67416d6accec3d7fd82d335d3ee" },
                { "son", "2a9763e77fe223d82901ea99bde8d3db66e4c10fb9ba595184c5d45ccfd04e3f4fd54629558d2c6e0dfb8dd4250135fbcd30f90f403f2afb3e84b999988f8df9" },
                { "sq", "54aebb2bb4f6413c31c711de6e6a91fec5df8590d9cf141d8afd8a38cbf4a4e503b00f78045aecbec3f758dc907f9a3746899ff8d68a8638e6fe3e78c1740b0f" },
                { "sr", "23153b9170c427fac12c4e6dd896634219f55f5b7833fc517578b0a11c3ca978c52ede8a3d768e279b908dd9a4985413948071968812cabb09a0ab6fb8e8b557" },
                { "sv-SE", "85badd82ef6d44ff69bf9e3858b407b5fc14ff3e5357e3816944981331ba43e49616e6bb054e5b01218d7cd6c1097eb2356da322a0f1eafe40e1b86c353896e2" },
                { "szl", "0bd47140c28aec6cf8fc158ecea5ea80bebc21c0f73747eddc1386b058ea9f0183ac9a506f2a3abfb83b640ab578a3e005ed4788535f89a25e37752f29ff07d7" },
                { "ta", "938e5ce4f6ccfb8cecab92e9cd92a232167b9199bdf21e855ea134bfadfbcfdfcc26db4a0946f6c34d6ec22a2d02e3f9bd11ee0c1c1321b4352e66cfa6667ee0" },
                { "te", "c1838cdf1983f2bf64f01de48649d70150b84222b1f4d9761dc59413e68787f5b0b316b2439707191a1d2c2fe61c3e02a1b723508bf65355ffce98dcf5d0ea8a" },
                { "tg", "b61dfd4f70106155eaaed54818466ff56c4fcc4ba9c658bc484de4325b3478a74d7460dae24604f5a787434eb07eadfcb9d1d939fcacf1e61e2bd11dc6322d1b" },
                { "th", "a98d91e3c07e1030483e53beabd7a7cbe1b7a896c67567a8fec3fe5dc96b812325609e476c048c3c967c7dab2285d6992ef24794167c55bac8fc0810260e38aa" },
                { "tl", "c6660e4380688c1dc2ceea9a4c3a498e738e1dc32f9cc76e06601794001fe0a1dbb0690c50fa63e82b6be6c6c3014c54b03f218f269e5c7c83eb23d9c0bece22" },
                { "tr", "8c9f959fad0e6474bdf2d35ef675c69d6a4f48c8479d6eef2ec4e7faeb6d7dd7a2b89df7ba90e8a23efb75aaf2708917bced0bba2c90c4159ce98ddf7e785324" },
                { "trs", "91ce502d479cf88a28df94f252fe28b9354b8d46a12e03a380c0b8390467ae9a36db378947f44b0fc19ee4b991e1bed894299472b85338ebe8a43e80a23860b1" },
                { "uk", "6dabc7ec9c6779e91e72423951dbf7982e793fd704a8e9123517d2571c3c9e78e58677bb3224784fcfa883f89aa88b46f995cfc6cb9de8d275b888c1a3e42a20" },
                { "ur", "899530f7b905816f07c1b31a88d56992e53557f07575c61ea1c6e1b9ac42b9e12f75b4aa0052744ea93d9023357aa50276413305a55325484eeabd9bf24f5b93" },
                { "uz", "5ee255c2c8e607c8106a3f666c4d882b56e0fe2d301952ab09a1f0f1d2306fe38227c4036d93cc9d1f0f0707b53b6229fb66c4362c36eaa3161b153343c8a2f6" },
                { "vi", "75456df9023b4868a6b877b14a845469dfe51238f910d77c436d302904719d0ed15620308f81200ec03d0d86a7c86b777fdc7ab213697aff57b0fd9d54348b34" },
                { "xh", "b16c55a0d07d34cf162052423be08cab34df1f9ff3da697c7756f099e049f3194d1366af3ffcaf6bc262fe7737b7c31de6b195ebe9cb8e39fc4f1b75d5ab0dfb" },
                { "zh-CN", "5d3df62d57872547356d6a8ade149870f9be94bfeaf05993d0b562896c56da37bcab5a563e3cc65edf09a31b606fd64a3df924c16e179d835e28296ae9eeba5d" },
                { "zh-TW", "ce12c28aab17bc39f9edb3701cde73ebf09ecc6ae761a4e4e6d67c7f158e6ea12377c453e039b34f038396eb1b86ea40e2440d54a1975600f468708e7e7d9b9c" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "9fafb1e199b2150ad63563cdbad5c838545104b6fb7cc40a21a0b3ae69870d35b5b0342795097a86e1c4c2eeea1578fa82e596cbd8ce771f0ee66dd80beed588" },
                { "af", "afede8c320b3a9b4869f8e98f825e0deadde1a606120736ee6a34f99a6e0f9dd35e494fa36dcdd786e725716d6af85729e6cd910256ee3bf98a20eb9e6b8d714" },
                { "an", "d37032adcc7ef23eaf90a102b810dd33098c6c95ab861ef887afa39a56994f9df6d052b3b4ac7191792c701331395c779dfc2760deeca62d1c1fa4e991a8ba34" },
                { "ar", "3a2641da52599274d1c36efbd4d87ce3a4b7eed7fe2ad51f3c56b88d037474fa71440b8e04ec49f826cb9faf18a408c77a41d7afb83fbfdca56bd53907b0c2d1" },
                { "ast", "99e769575a9687e57e277df5c99b8e6339fef8c14f0b1815084477403e4d279441b0673338c834161c0c334fc63b259995c0b8e71d8ea673defd9f3db7fa47c1" },
                { "az", "3bcbe131d9def58f6ca067d8aaef5e5744a57ceb185d95fbdad1eba0584250c18c942be85a1ca6ba1074337e6a40a20e5a4fc7d35832ea47b85241170ff127f6" },
                { "be", "1b8b00eb6484d4b3c5e918b4fa970b58ff1c1b6d19f45869dc5b2a9c4449181f0b31c3d7369e835955a27fa246cd5a5c64d29965cf52bf7003a8a3ccbe7d71cc" },
                { "bg", "c7433ee8f1c99b362a70b4dc753c8816557302fbcb65ce2d07c830aba9f15fd7718a7f949595add238f4a9c28a50c3f3cea305ff3cbb2167b07ef56ba5bee5c3" },
                { "bn", "f6b826a240ef1577c4d41ba8fe7377aab99addda6127325bedaf93379b97829c498a01a26a681a548e0069a1d920cac07bab7669846d59c26e173640f53425f9" },
                { "br", "40d0f3d8999bf999d3a2d5e4b72d131c5f58b36db23d5fa31585731708106e24998781e9432228e1a7cfe6f9310ada691255775a2af670aa5c996c343c269258" },
                { "bs", "6fba85120626f0fa4ee25f729028f0bcb3e7befeb37866752313c4db941569d706633aa0ee54afef8484adff490255ab48d27f8ab47727d689875e7280fc1852" },
                { "ca", "9f2f0120b5dbf20cb0118b56c23b99ddcd8866bc53d588b265c5baf0fd5f1bbaf4c80575ff21520919882531590333f0e3cecdf474ea7b27239ef422ee7b1885" },
                { "cak", "84827cc7d68e43e03d5ae3ca320b0b33771417866a6994c51b4f5fe83501c7a0fcbd1ea5dbf7b6a4659ed6c71e3608661bb46c84953d2b917ac33330179cd7b0" },
                { "cs", "aaec9ff3ce7078ca414770ccf191fc15ebd72709f452d22a308946a1273a443550fa56a496f29feead31865c7532dc14972150ad3fc0d474ad80983ad9c8bfc4" },
                { "cy", "f4b816ec2688ac5046521d37849d9127e14129fedc555b2d2cf691a620a8e3b457ceb925f4ff9297c73d254676757bbcdf56b1c1e18be618c592597250644cfd" },
                { "da", "157d6584678ef2e3d4b63f5df5667c1bca9850512888763fc479431746a24e729d89e88fd9fc92884505356501738f23ddd86a5bbbdd02058478498a371992f3" },
                { "de", "fb98e76e24978a770fb29e04cfb5af4d4ae7cc852766dbf9b3de2b1618f728d4aff8aa52300a35286bd98d9dff487ecc18ca59e4ee139dedb51e36c9cda00537" },
                { "dsb", "0da54cd3cb5828242c8964609d418dd359fc32a31091a78f85cb1f009d74cfc0a25449a5a8c8e439c527e4e4125a6d08c30b9d4cc19eeda9197441b30b4fc0e9" },
                { "el", "8c75122b321b59b6426b763e0ba868718e8c0365ac29d5b1f868442ad01ba7c191539b1046195fd3e00eacc3a75f2097f6b5fc2f16f3867d568012442b62b7eb" },
                { "en-CA", "00e49d8eb288b93c4cb0901f17cdd5f2d67f6aa11a435785d498b2b5d5268f0fa6d85a7e305e4829ef77145499d6516a40f8f477a772323a1bbbe780e552c63f" },
                { "en-GB", "723df6b65f4d3882b01fd25179dd290033460d52d8ad1499613bcfe034c1cec7588924ab474c08c9eb348c6926a90cb98debead7bfaee19079e15ba35a955c0d" },
                { "en-US", "ee0e9026f9fcf97455539100db225e014198540b956854caca2e1ce383fbd761f14cb401b04c812df4a6ced85a78c66a4b55c7f12f34dd07841ad5d13f68bc4a" },
                { "eo", "e20115b01c167fd134e501fa41900efc990b7a555d21b7c4a350e18fc84104f26818c4971ec1724fc0ada2f50aa9b40881b19e3fee873a62ca4419bd1e28b9bf" },
                { "es-AR", "9e487f2d91fb5e4200db7c24bf5e785c0b81223862d87610d6878052d1c9ff82b501c284e26bd2fa3bc55a5a004d05889bfa03d7a37840ad93677d825943e523" },
                { "es-CL", "3fa4493db6e080ce8de447d1734dcc4794408eebe2e6ec36cc0eec95a39549f15d2784dcc0869aab4c5484fc651fd9c4b8fb19a71dd8be3b8b799424726b0d54" },
                { "es-ES", "44c25c9eb6e239f4851f0ecf5929ac3a995894d26784d75a816d61073ea0227311c43524824a904d4d5bc7c648a06d1da096ac6c74b3f92d8c6955e0c8bd1131" },
                { "es-MX", "9623b3f2921587f0f5886625b82c9ca0d45adc534780123ef8ed4f910d8510e1cf89e47d89f4339004c8ef380811103394dbddda0c7889885d0b194c25bd7d84" },
                { "et", "24cd00f021b744234ed151bd67ff2e38976642f779fbe627608ec26dabc18d8617d30cf441fa1eaee339ec3b40aa4b8424c5d97ad32f5bbee336f67af2310912" },
                { "eu", "5b8aa26c7a47db91a7b48aa677a60d161924662a123e36555ea570b5867beb9a317867d55200dd68a6f689f4a14655d763a5fb72f3601b9d8fb69f7e298b367e" },
                { "fa", "a933709dab0b784192013de1818e8be28eb9ca3f11a737bebd5edd2c412392cc64f815e599e4bed9d9e0ec8aefaf27d0ec318b684a00012767f08894c5ff48ef" },
                { "ff", "705e63c4db1b17b55c3853f85f90e83a9379460d82372b613016ae21ab69b8c0d0e1379cc91e0a56d489f8a1925a9d5946fc8fda58e6759af407a394edf05a5b" },
                { "fi", "cd910916f00692f5e2957b0754eaa85adc2d6cbc8b50f4a4a0cd17ed3cb92e2cb2f5fa728f4c9aa5babe9cba60db22116ce3c429f4a5cdc26f7349ab61dac2d7" },
                { "fr", "625e32a9aa2c92f78439ae2f0f4cfeb6632a0d39449c9f1f4e09697ecf80a739867251b517d82c60d2b9801e2bf3138615c1c91e90dc25c9c149a0cad2deacb0" },
                { "fur", "9460ea562cc078f19bd2324f95202825adde7b6f64ce6eccd825b48bc1cafe0f7f96921b833e1d147635be634a235c0acd916fd840d06298336a79a8c4f327c7" },
                { "fy-NL", "8535c697a913d3678b77932932d56c5f48941ae1496af0e3dcca78282b01028dc60e710153c7d998f7d259be3657b72d4de1d9030d6f647f2ef5e3eaf7410da8" },
                { "ga-IE", "ced36d08f130f188c9becd779c15ffbac771e7d491ecfacfe8aef08f976bec1ffc70108619ee400e1887d7388c2f1d91a210ea22f26f6787151020f892d62bf4" },
                { "gd", "9d7b8fe863f967da8f43c83b9f87ef690f2795e35c2571f39699ae09ebf0d9b58331f2c52fe2a4ac9bd0f12675656034004270e3ec78bbbaf1cbeb4890fd379c" },
                { "gl", "a2fb34b8bf3f68d92069f8edc1afa0ca9c8d811f671b748f4048659a5220c6012cb72794dff0a9cb0b1a34c9dd40104e71d4a7386d770cba4c5a62a4f78f45f8" },
                { "gn", "2af7458ba7101cf54a47124f3ff745351eb9b7222b24afbd9a0e2ccf30c68f8876e1ad3927eb5688f6db296403a217cc25b27172ca0c635a5b9c1d71ebd35985" },
                { "gu-IN", "82b395d1872cee9b4b45c11a524e5925d6f65e63282b9ca39a33bebcf82ffadfee7dde7887dd760b8a107a2938a3c1a8fdc2d25da34648ffa4edb7bf32aae638" },
                { "he", "b933b292c21c642b157de27de4503695a01e2a88e137dcbc67d00f62e1c5aa3a1bff0b1e3ffa632a2837fbc3dbc10591c172ff81d2756e44604c4a14534fd086" },
                { "hi-IN", "cc7dc5237e73a684df2863ed1567c181f1e9f46bd639bc60afabd7064f5a27a20a3ffa35f03b97469c764f18138e19717b6b65e6a28ff49721a0c7982fe4ac7a" },
                { "hr", "c60bf69660523eacc23183519a7b9ae82c248d5edb65086699f3990024dd556ff1e0249e42e362462f278d2339bf0d385da8f7cdc3e06064d8240d39535c8e0d" },
                { "hsb", "83aa327a048f49e8b7c91cff85defbac7a632ecf8ace138675386052c91b9a79d59d0063cf62a69fd9e367771665c928b9c977e9a5cdb6e10789951b0698beeb" },
                { "hu", "5cee82006d87cd218d09c3bce071d1fc5e476afef32eb411311007054586e5905d23aeb557935b9945a6ede015d69a1f8218cf5c4a081732862cd2f8f7199e4b" },
                { "hy-AM", "950e6ab1cc533f1006c69a8ced98e0e575544df60c85d62fd8d44396a429126b2ee00962bc70f71611077e95d24c039075d99d9ed3dd418a94420f4b132d893c" },
                { "ia", "fc253a6d571ad212ca2ad67ee74722e9d34fb2e887cc872cc47fc178beee9afaf6e5b1d9b88172e48ef1e7ec2deed8a00fce587b753d57daacb079ebe33fdf5c" },
                { "id", "43437c50dbc6946a64225a3eed269bbbef6349168c0732d6dc085b559fecf2fe2ed072749d3d96a0938d308984e0e7d2fee3ba4df356b3d62f5c4334f355e9d1" },
                { "is", "975cf5df22d938f5b662eac2fe82f613195f11f6b9967db88b5b9eaedb52d7baedda77717da79618e710301e9894b82a5a92291ef2bb4ace410ca5b090e963bf" },
                { "it", "7912afacc58f6ce71187c91a860ba60642689bbedb3236a280ca148d551967cdb97ee3cd646d315f02df2c4900f930c7cce5b701a6c067446955ab447b6cf517" },
                { "ja", "0cc06f4d557489af130807f7581feaf6ee203a571310f3463b46d3d6b8ca0363ba6ab5345af29167ac07fba3a2f969a09aea867ff7d926bbfa9fc30515766569" },
                { "ka", "274b6bf426bf1d8c7d5b30a2c81f8fcc8ace219805987255a22d09bed0680471bb0e99fa4499252522f0536a308dd76adff85c07a57ae184b9b4dcbbcdbaa6c8" },
                { "kab", "02348f5eb87ac4aa686c22729a585179064b0a14024135a484feb6de7c4ec3a83a270bd7834f190ccc4615e3eb41a7052b1d088ed5f8675d11bbc86d9cd4a4c3" },
                { "kk", "4789babc9da4d146b2dd9ea818602a2da62697afb9358cff86258cddf8dc52d72dc31e396cdc7ec1c2b8dbf8b0cba717c318dbac9fe6c9f1f0250b9c8540ec1a" },
                { "km", "5b0e8b46f1a56302ac3af53081e45bb6e8c88e2fe64de688984de5f6aa9006cf7945c81e64949acc4ec60d701520b03baf7ddb6c601a8765f91660f46d186388" },
                { "kn", "ac64206f553b1142615b801ae1cd2991c3ff63c5a0b440b7ad88c078665f8d65a2571cbc550cad77240d3e9edd124f806977706866fdaa5406d8352e36591d6d" },
                { "ko", "620e028a1663936d43727724b50b3429214ec1982d156295c8903309451604eedf09faffcd83bea0620c9b092e15c69102e02ddf98321f33a70e0863f9fad58f" },
                { "lij", "01d8a7abad93bb2f1642ae5f9cad98e4eee7f74d1a4fd8dc66d5c8c4afc3e83a4795e981f6047e6f88a8e28e59d206b294c4bf66804f1fdc61470d9ec8ecc8bf" },
                { "lt", "cde8a78ac9c01d657da31dc3771ca620cc0dbae90393d7d16b1305cc30e5e7c7aed3670169aca7544b34069a8fd694a4f0e99c325a9f5fca34233f9be11deecb" },
                { "lv", "b0a480cd9839e0d3fd8d1705359eeb95f3c7f589b167bb28b9ad1795ee579b3901029a8508f198bf9f3d5fd0d764ab99abb16af0a85bccfb0ae4f7e070c8d0b3" },
                { "mk", "814289ed45105c61b5aefe962004480b171301c0a8664aad8018590daf3945cb1989385305850a6901294caa26cfc568b0f0da6f5efbb6c50ec1634202bc7a51" },
                { "mr", "ab324d2110616b876cb521f20a891c189e3631d64f219d4d6084720dc3cc32f3585fc053757f4280b9b1b0b31dd9c45faef7780ca9aeb7af747a023e93fd6bfe" },
                { "ms", "3ff5d9cd8d8c01edf2ca58f57dfec47c0533ecb6f91514f2e7bf4d0ee42cc53b5af929d61eaa01b8c9cd7aa120678b9cbafde677c63900e9ef125f241362d323" },
                { "my", "9513873af8809df1ff9cf6debed1eaa38cb9bbfe8aa205a37189453defcb23b6395599ad52300767155c8a43c703bb770cdad46f10189afef1a9192243cb17a2" },
                { "nb-NO", "5a8b2d9e576851c9036067069c4c6cd422722a8063fdcb451d60a02fe41ec723cf0f4cd506ae2b498b8d89764219e27d40fa0c924d3e29867c8bb1aabff63315" },
                { "ne-NP", "4dc62a7d4671733c288a63489742401ce006794857e4e782f40db05419283e5aaa141a1fbb8606cbe06640bfe89a2cb8311457d486432ee94df3ca4263753d79" },
                { "nl", "db62fde3f1b39916e16b38a78872fc455158f87bf427cf1648aa904e38addd2b9784d897d73cdf637991557458d8a459d4b80f51d01e76bfdb953d35094cfb8c" },
                { "nn-NO", "a9942c4213fb5b1b5d2999d59a0000a9f91292a3a13bfad2a29870f1e24541b16971eb9a767ea153ecb7f92059cf75e2ef610bfaed0bb1002760c4f79a1b9328" },
                { "oc", "6825b4309dec5ef901fdbba2c6fedf845f8bf4227d6c2cbb9f2d1e9028cc1ea83c449509b28237bd58794040388128b32ec88ed76e6d13a833bc50f1b68807fd" },
                { "pa-IN", "719b27b1a033b1c2e5db81e2912ed371d38c0807d1940c4289a495dd3a53a03141d8af38bf1ad5be51fe1baf786bd540a32d922a2df92dea4cef7baaba91657e" },
                { "pl", "96e5ee77a43d55f7b3ba0fc012bc41f7f11cbe48e960dcdf4af41c92a792605cb1e24c13766b4c62e65d0bd975fc66c6f05e49631a9edb8860d87f0918e2acdf" },
                { "pt-BR", "e1cc3d8ebdce61938ef702bb1f28a6e5583c1dae9d31d6c84e163c0cbc3fc0586ddde9dabd5778da1d42b48fbda66e35e009e98116afd23dca736429d910c776" },
                { "pt-PT", "5fd4230a109ba51bf53ffb096d23064ab1632f9b71bf9a821fa2670b6bdf221590f4bea9b08e24e51e2646370cf53fb674dbee5abb12df6a1474bd45a6f2dd70" },
                { "rm", "f0d661d4e311dac4731902a9da157300754e9ca045ecb6be2bc0ee9956bc9f364890a56528e952245881e2fd49956e82d9644fa6a3398ff03a96d8cea9b1d6aa" },
                { "ro", "065ef28240c68f6fb31100291dccfc5ab615ca029d801df514b7f56dbcdbd4cfca00734a0ab5bb493b66cb04acc658dcb4c18f294e552ef3d5ba33a4110683ad" },
                { "ru", "3de5583e3643bd162ae856b050afb5f8a576a47a7cb7a871c204cf468e322301bec60bacf252bc6493dc53a5053d0c56d6960669aa2d9edb34835dac890c5365" },
                { "sat", "9134a9d48814107e8d11a17ab68366c4ccc40ce179207b0c7f7fcefe5af48440d471cb7dbd0c67304ad001d1b23286978641e0d41424d2da7848bf0a1d5d6dfa" },
                { "sc", "0161e9577e0762e200abfa58aebf64c2b797f542e8195b943fadee3bd508a927654dcc65c45ed445375eefe961d0abddd2689b731afcb7e5835f38707ea858ba" },
                { "sco", "e4e8484f3c7c7b53b67dde4318201b9e0915ebd068fabf7fc26ee69898bff78ae707ddff17c7326d0040b6e8436bf363e8a714dabafc6a5a468fce6bac8a8c9e" },
                { "si", "d962420d500497641866a9218fc2b896eade4b786dca093bdb2f4759afbf31ac1219b84a554840424c712b0c5d90afedea5392cfd9185fcc2434599b2b0777c7" },
                { "sk", "856a892f225abec9796cfabc269ea3a04ff951c8d4dfbc8166a5a087d35438c1dccb863d75cc963804a26ba62e7663f57a315120140772729736685acf7358ba" },
                { "skr", "c8ace6daf739ee0a34446f246775b2d31db9ab3bbfdd4d31ff15c0cab767398cdfad10f25b808b7a2fdca7e641af59afa07c5ced0a5522c1931776092e55b4c9" },
                { "sl", "a6ee9b3a79721a7a377deef66026180063b834ca08b052e1778d8bab91bffd4aa61f4069d61114e7f7af1d15ebe0e81292cf3351aa0c3375ea3aec0e416c9d29" },
                { "son", "36af813d92a3a682d05b9114c93e27a80aad13c2905b69df39b0be0deee72a6e24c9a0160d7822d17f4f1a4b422067f582314cdae3a684ff90ce83582edefae6" },
                { "sq", "9de21ac3e16a7f779da997a07cc2a067ce70c68a8e1ce08a77fde85235a5c49899c6133cb234d624c670f62e315ed73da67185abbbb3f613a3600cd387e203c7" },
                { "sr", "4650c3ef1444ee20463316b1ab99df6d16b29cfc3f05e067d8ff9916f87dcc47bc814d34c4ddb6e25cb2da5c6f418fb28ab8b1a9a417992f7b8b6f498b97e844" },
                { "sv-SE", "2268fe2ad6727d9d4fc5e31b8cff5150ef85520c1a2c3649a1bbad29d7fe41a223fb98b1baf843228aecd901fbb87e7143e4c3c3316f9f32abc3b1b05c5056db" },
                { "szl", "ca73b4a2e6851f385b5b84c22e5f7f943cf8b02a86fd22746b44b59af126323a84f5c957c30267522d18fde2c30d9a75d09d2aa2a465c9758a286fc8921b41a8" },
                { "ta", "85565779fb996cf1167658cf2200e9e7273fa7a5237329bd3d95a99f37aa7a7d1ba224f88127c7f59dbad395b68617446c4c55e9b4c7a8c647a58986cf463798" },
                { "te", "4ac8f183082d1b58f621493b740d10b97cdcdb187fad2942b13645ef4f660d284c0ec777d6375b49e72510205b9712333332ce50d7c62f8c56d13f3c52e3da48" },
                { "tg", "75fef5eddea03eb5db41a2f1bf370e1934489538c102785aacaae4d89530ef34be779c9e11505f14f9329d0b1f247e7d37f5a80a7342d2424ec026c2031d9fa9" },
                { "th", "e7528f91db78c6c116580f37777c1c17b7959817957f533bca08e020d8dcc91c563f27eb32241ec04ab590c53fb6acde459a26f104d9ed46e6d2bec74db26f1f" },
                { "tl", "39ce6b7c3423f468c7d08a62f8fdcf19aae5239f4783d6be27c9422e8434f3679bfc58d83b682e8319b31c70ba98cd465cdd7b3d364626f44e6c1093b238dc04" },
                { "tr", "ad478728baafaa943cfac80ab26e809342d6ba0c2bef94534648ca76b6c1ddcece3e966e414c761f913a853edbcd8db1d8c4fe279d56c2a0b7c0534d4e9901a3" },
                { "trs", "a1af05080d073ed6f4571a90482187af4fff5a732046e3a5d36540ff886cd02f319516d22cc88af057d10f4966713328b7ade9807bcc0544cee4f055cb2c0927" },
                { "uk", "6ecd33f0fb0b9f4f3fbe51c3da00f1c68693e7627ce3acf36e28aec55e4ab43808ac833ac9d4d4502b4dddc9cdd5e1770bc2865b179853359fe90cb72319e64c" },
                { "ur", "9b2f8f6bacd40d774b69be889ee22d7619f62d6aa3050402dbfc8a508e030f74e9d7b343017e7b96eb416008078d029497985cb5a3d4d0d9b6a847b286e6fbc6" },
                { "uz", "dbe14c033d531c35842eeb433b8264c9f687ae71ae86b6f164fa437ab751265645cd924774cb9e7704a670bf94c0d3ebb1d23b91ecf88a0721561ff126dbafc2" },
                { "vi", "6f03dfe6c243b5b0fe6229b26fbed80a7f7ad8e139fcf60c48cea62ad518421480abe3fb5cab985edfa242a3ed33d6dd10e097cada83b6c89558e996603f99ac" },
                { "xh", "debbfa8dc6b0d8ce0a953a3704bb70e6a93fa6649987aa211be0ec8157c1a634a63d8c14412a7e49fe34b2904c1138bc62efd9c524c592face1a73a1a5f77a1d" },
                { "zh-CN", "ae3ed3eb4581f5519307258b2f0c7b5963e078d7ce60a460124432a27b045f92f4274c46111595461486051f3e442434e34f6847e18dd7e61d5e5250e2fefc7a" },
                { "zh-TW", "088a26641b464630c840508484aa6c2bc783f754f62cf6c3ce618df5b6edf4f314e165aff3ea8e19d2cf15eaa152669ae0df4a8f9c42329ede8fd8322f3cb756" }
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
