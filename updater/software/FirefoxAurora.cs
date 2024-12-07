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
        private const string currentVersion = "134.0b7";


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
            // https://ftp.mozilla.org/pub/devedition/releases/134.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "2c9d644fbb13a7538420be6fa658a6dbf169303cdde2fcea4f98a7d2c82ac0451164a18f080a9e77eb47a2b73f4120d60c0980679341c434b5dfdcee078f1e19" },
                { "af", "7f6ddc6b1dedfb99195738d86df8d25238a4777c0c65e6bfb1e878948116937d8687f1d32ffed7edb684d63dbebd37c64ae64b1b1b07624a1098dcd2d9e65f26" },
                { "an", "6baaad5f75290e237f77e5dc9bb2b0220a4df7f783d1f9c64d59794134da9708ca66c53e28ca9538f70ae81b4bc19681dc34096f0339a6fb8ef612488d6f2156" },
                { "ar", "002d52c618bfe66a15c55555329e722c4b85cfd3fd490e3da6eb612d5a89fadcb8ffad755c8ab9e6556ac51449ceb08331d2f3676d7d6a5460b8245959c34a89" },
                { "ast", "4a8df255228285fc990d25f81006b3ca82711db4da92165b357c5df807e69fb1b27431cd8683f231197668ef7c4e0a4a83158fb194ad3fe06edb7054391afbfa" },
                { "az", "3b55031ad6d9034e56b81be06305e13db04377af9c699ee5b346e7bd6964adfd405368540ac1cd37029aba3733ce0417301631b20771c5811f3a95fded2c249d" },
                { "be", "9dd0ca5693ec07bfc6a4696f20adbf8a288d0ec38f5bf340cd69032f736abeeee3e2d394fc1831ce69313b63581416a7c4cebed1bd2e0a99b2168c29220558bf" },
                { "bg", "c7a2876092fed9a037d6f9a3c3ca85f3bfd7f3b6e1e30b6fc2ca20f1f2564eb35c65ef9fddea622a68a75673366c41093e10535e21320c68630b6e8b94a8362a" },
                { "bn", "49598d1c415d54f19308efca077c4f17ddc53fc09ed91355228f256a36e49e188630dbb6a22d7161e33b364d8186b3b919c96794456c5a625d2c8f11d48484d2" },
                { "br", "890e5b88bba574343c1db6f51b8cfc8b3e090757fcb56373588d1566c804d7979d7808ccf335fbe4dc88118fa89208b42c0991637a1b1d94a017d1e409183dfb" },
                { "bs", "e018737c196fc790fe1df38b3693e718d697761f28af4ff6672477ae743d97864f946301170b7252210adc60453360b6f801ce24371403eeb064f44f3e9920e4" },
                { "ca", "be153c56ea9f4b3454eef77d505e2323ded77647255cb94f431761b2d270f4ed8a74f46fe743b75ca1ca7a834c1243306676f3b85c49b962a4a9789e8a21770d" },
                { "cak", "4aad36773135fd79e5ab377a8c02033f9d51078bee1daa94c6b9da4d3532242dfcd6e68a7935214017cd6ab249a2f70c675d30cda5bc440bd4b8b23b468a65ca" },
                { "cs", "8685b153a9391fecf3eb32e222f989204ebed6520dead4dbe4b1288a77a3f1e8a9c5f9ef26725e4750e0c793414b63f76f98a314875f33812de905259bd47efa" },
                { "cy", "fa033dd4262fec0cd21f5430bbc320a8f3a2cb372c2d08f611541d8351f5a0b1c40f08fe67e6fa0794e059c30cfb13c5e04b5ecc08ed63e2f214fbd593c7ba16" },
                { "da", "6224459653e666b34cf10ad67cd912fdf17558c23867c33c68d7bae2532d3b6439aea4d1fd6d597e9f1c4e0501758ce48b79374e11fb2376b1df3bba6e0fecd1" },
                { "de", "baa5e5993eca5692d77120771b4515f2efda9a6be782616193763a02b8c5835f12fae8105b20996f1cd754d825252deff0db34ab126495c215c0f788206fc245" },
                { "dsb", "4ca11496eae9c565bdc6484c1bdeb7f7eb9a1fe85a00fd0df1efcf098e4cd37e0a4d5f0119546f768048bfaadc44a09fbd647ca860526507fc3fe80d08bb5ffd" },
                { "el", "68f2dbe57f65b35656a0d4a1d5d70bb520240ac5267e8158bd25a30de1717384ceb2a879b9dd821782a25d20a3a7dd32780dfbfccbac55798bc7f29c43010274" },
                { "en-CA", "6f71620775c09851e8b248787faf3de0a38a50d8d6a4e31a09c869a2a9898ffd8f454529b6ac4759ccf71b8041381c77bfbb9879c46b15fde1ec7160c20e12d4" },
                { "en-GB", "58d5d2a5092600f2857c77f351cbbf7ffec5dcacfce89823917aa6404d9354aa08eee9cebee7439f01aa90c58d4edfc7caabaea508fa328a78642da68a61bbef" },
                { "en-US", "53023229dbd5c4e01741d9a5f59bc4e0987e656e73dea81179073c3bc24d35aad0703fc8c4ccc27c653d218bc1f3445fef45687f9073cc08a53ebb0948791047" },
                { "eo", "7872309274f8c9150b592a1b0aeabe3e8985fd69e4f5ac617851302e61a424ddc3997b1f4e4fed2667d182d01bab4b1f5c72e12b45727edbf936ee7a3bab09a8" },
                { "es-AR", "aa9b85264796d4a38bf6d7c46d355de46e1dc1026cd0a6321d6225d97fd25a83457598a0d99372d162c6bdadd7dcfe50d76745b762772857d440cc1b11a97e95" },
                { "es-CL", "872ac5faa8d658bb445d971bafd3d8f54b6f804b7f8fd5dff2b8a550fa0fbd2744bd135e827a9b97cf6d4886536f4a86ee85b49b33c5bc471ae874399ec53c87" },
                { "es-ES", "573edd0f996325828f569acd91d4fd1922ffcbcd133d0a94992b44390cd9817a929cca6721b2577359d0430977c2daa34ee743d9abd10f0fe95194c8393bd228" },
                { "es-MX", "f4eb1711bd74a3cfbaaf3063b656b823c5534d398fabe7cb16b789b6ee226149f68cfd7d732a04e8ed836a1c00c8fba3ec5cb804b5af2adf64a042d8660edaee" },
                { "et", "553c4b59ed8d7c2acff46ca067f547575a109b48b18718f46b8d4f6ea9296faed22d719f3cb52a82876494d752b7e9d98466ba989974e0331207cfb903f08a28" },
                { "eu", "45647e1d17640d763d8516b20b8e9496afc707a49b810f108b716d2669ab82f11534ff9ccc72519447e894b896ae84e52748e10f301840cec7a5fbc5a2e83b94" },
                { "fa", "e57f0cf0e15759358ae910f554e2e12af0a640303b8b4bec86208c4b224b51fcae4c65c066afd792d85115a8777eccddf7dd2a15c804e62c281715d743b9bd42" },
                { "ff", "c238ff6b83a459b34b4e2136db784dbbfdc2ad98f7842c7ba9f373da87ca2021fd68a431fbb810ad43c0146d442ddcd4310b8655e475b09ea3b5a40af10cf256" },
                { "fi", "29fac418b7b1d72faa790ec984c3dba26309832a9cde2dce3248651cf831bfc9f8c62be7d74ade9caceafb5fc9870ad8d049e6c1a7f6b94e0495aa83fc75800e" },
                { "fr", "245a0bfa9825c1a08b207164b6e9288bfb74d615d604241aa3da602b2842b477425ff73b925e6323998dece46090e4e00521f21b2e9e8b199aaac72eb9c842ce" },
                { "fur", "7e273289670eac75f59bd4119f0e96a21ef371a8796efe651f453623474b86feaab018f917b5a22673f2da1a49aa387342ac84616c358e6e92091062c1973d17" },
                { "fy-NL", "ab4d1c067dc67db07cc5fd79860957cc43f9b030d539a8af97cccc5e55afb029bbf3ac64e479d079fa4a2d99a9d97d43ca7c09c436bbf580e448171d9b5ef5ed" },
                { "ga-IE", "4bd015ab40e6039e69a73e8764cb993623f5b77ee55ad2c5ce7b4cdac0a1feef30d20d05b4f33d7d92020eb668fbf2a87267eeccd0863b46bb2f261974d3ad06" },
                { "gd", "7b2b49a09b51a791c76af0936272509188bb4b96418b338f2852cca5f32e63361a8acd6b0c6aad82805933c105d35c17301174bd176e98a13afbca477dd89992" },
                { "gl", "7f0093125106a2fa99b9a0f31511c46b5e3d40a4e52065c288158acd822f2f9fff7121cf70a84f9772105777ed3a4fe8d3f01aa5619cfba24faf459b968a0e67" },
                { "gn", "0666363845d897747b7431ea791b3ae31cf7572283d895002b7d0e4d8125cba2ff3786bebb93eaa16a7653aae720c7262ec333a3d453592bcebbb44019dba8a2" },
                { "gu-IN", "a0cd17c30544ae6fedcd527ec781bdd728771460be5838959eab8de93be6a744131aca9e7eb5f79ff8cd02e04baf1414ae94a982802cce7939e1caa031a75fb2" },
                { "he", "9429595d368f229edcd10b0a4ddf4357e002f4f0360c5d0d91d7a1807717eeaa0545c51c4c84614847de40c456ef9b43179fc343b34c00cac3c747cc49bf8d07" },
                { "hi-IN", "1f43733b23da1d73bd832a2f5a4edb76fdd2ba73ac95b5eee50c331740eb264196e6951bb5d76b3fc3940bff42113f9aadc0891a97db5b3c8ac1f62df8fef142" },
                { "hr", "9b9d3e8b4dae19edd4a3e507a1db6e8499f306eb20e41b254139c304fc5aeb7cca1f1f70d9ea7085a4d70c9edcb5c2547730ca2fa45c13721ef6aa15d6331450" },
                { "hsb", "7f74c3da23949b499a9621aed4d67f06515972b1e54b52ef457ded13d7cb11072032b0dbba162dab9d97118e4b6624bed864095c3560a4bcf0e62b078dcd3420" },
                { "hu", "eb4abfd632e676da8b7db051f3fa94673bc52ea6a35cf88d158a52fd67b40ebfa0035ba7244846fbf1e59e01dd7d114f29eedb963ee2b6b10f4c58987e10e284" },
                { "hy-AM", "1bfcc7ddc715cb84f93e15d3e1ff647d7a58f556f911a79dab8e8049df7b272d59817c4b7b8ce39f0184c7ae9eda9c5e8ca5635fc68eae8d51dd52fb85b8c8e6" },
                { "ia", "ea6a1674c7c23c7ca44ffd3ae5812fa18949c2beddc71ff59cbaafbfa37369f5a7c287c402461e3c5a4e575484174c327f88b76dc7c1364ec3cbf87535d9d6ab" },
                { "id", "1638e55d80f551c617d1e8adfe255cbcb7852425c29d8f5fff3d43e5ec680086c66be24b8bb40884c345402e101c1baf1f73b634ce3415c2fe8e7cb6d6f657c0" },
                { "is", "8b22d53559a9a76547fa66decf15c88f398f25fceb5a32969315d3f74ab1d39b431933c8df05b27636a5482752758f83437ca79b27082482d3119d47e9f6c9c1" },
                { "it", "8cef66ee8506d6f725e8726065aed11a3d16a1c5737aeef53daed41996f42725d5f6a4086efc26a8a2bb0129272f36f1dac341ef1bdb7015b191b88975b99ec0" },
                { "ja", "d06c10fcd18ff6708bbde39970c9643b4130388f1005d8888404a714fa601c10fad274efda7fe4bdd0ce2eca16ec39249ed0ab47bd0fd7aa8eddc2517b73a57c" },
                { "ka", "05b767e0dc289b4f755e9c022d8cdc76a7aef0c32ef117e03ea6aad5092bbda1c6a7975e7e9e21ae6a0a7ff4918582805f61a76371f2e4ef59adafef86b2ea0a" },
                { "kab", "faac06d9c089bbd78216ae64a0e72724bd17912763f539e62c90c0ea4f56758e0701817bfaf38a3a7881f11bc18364674664f68e7217ee32e50a071bd9d558c6" },
                { "kk", "a41ba8bdfe672c56f636abef3a11fd64446c3572e2452f6745b1664c87937040707082b7c7e255ec02d5faca8c255965cf3d70a2aa2bd024d36b04617e9c5fbd" },
                { "km", "682ca749ae88e53b8fe8bda196ddba7dd575bdf265ac40be724b6558f043176bbdb8f596e740ed63122ab7b8a5041cf11d6be2c9aa8f68a5fb2953e97c488a1e" },
                { "kn", "59c5f0a8d82403299c75bc320f00acfbda28483e6487938c17ad21e8b5183915b71b48c5a831523574d7bdb9f0b318f34c229abbca72e908e1820be4ce366275" },
                { "ko", "9fd65f72f07697b6f533b7967b5820463856b8c1ee82f8007292cc75d80791c06471bae7385607bf93f88b400c6cbec9215c16280f3abc50c8976694f955ea2a" },
                { "lij", "ccca206c19a9b97fb74bd4b5ee646c9128c2d727ef7c7add9fbc73d9d35947fb30952369dbd9274ef29aa55eb7d83a00820cdc541355ccd39f1b87ee3c0ba50c" },
                { "lt", "88af8b1268303f40b31d677e0610893cf9b9c192e93dcb5f6c3083a48cb0ea83daf4293529adabde8ea6f4ca37070d5a7d85715dcb9d25f377f8a2a66119308f" },
                { "lv", "59492a5f64dbb521cda7808db18db22f49ef7bbe9cff75cc98a42efb05db157779ac2cab8e2e7c2315f70e6c182890aaeaeb590fda9ba1b017246623287c1f40" },
                { "mk", "c3df7e873a83208d4f05ba24c7aa21aee20ec2faef1aa30eb8cb8797eb95056303e6a49ae227f740411d3bea1860e2c126b1e8506958ba0c8c332ad1ce276311" },
                { "mr", "8b4741094644a930571d19f8e990b4be37924af3334a75288afc4f8edd8e14b75121ac1df2066a584368d02c9cf84d4b2d613aa92ed5ac439d7262350ec0105a" },
                { "ms", "9d33619dbf4a0c9438f56966a7fe81a88857119a799070396b272e0f8e047e031f8a19da1b2d2ab7270b33a134e2e22036ed686e81e28c75cb6efdf2d78cca0b" },
                { "my", "8de99ac1d6c893e704717ac4abbdc339132b750f75d26d226b3d3d18158764d03de51e04bd05b42f278fe346a1628d6db83fbe65e0eeeb5959c999b283213b09" },
                { "nb-NO", "6cf15e266c951291e428cbd19adb57177c0ade4831cc34813987503e9023db89389f1f4d1d7e5371fdc4daf935b7bbe8da87fb1b778e240ec0b51f5399fd871c" },
                { "ne-NP", "3aec027a09bb6be8838c4a48d5296ec55fc30fbea59a9440e304b5547dd7a1e96456a6472e8062554980f98edbde30012ff6ab026d58bcf511a5bf24bea36aaa" },
                { "nl", "31724588de950f16ada9e8b5a07da1d4d548492aca8a0ff765108fa8dab9fdc2e3c77ec35953cf1c66fd664fa599f357cb43719f27361f60696985885ff3bcfa" },
                { "nn-NO", "c191a91db70c6b7f67b49cb853824bf546d0036ed611a1f3c64188f9aa3a39eeb5718c376a418d22112b73aca5605164cbdbd15688fc2e6e7708770cc5d03f3d" },
                { "oc", "dfe6be21fe2d9e215a50f924f1e1feb0b92f741f35cd0ef9fcfca8553ae654fe8448090e1bd7c5a701fc36021104754082763c1de560446d16097cd583b0caba" },
                { "pa-IN", "b596f50a420e4d76a387d488463bd9b77c9e14c14dfd60f27cfac4f3eec7116c5008c88e80cbd369f975772494ee4f992f56b82c7194bf993781b87924f1971e" },
                { "pl", "fa88ba03167aef92933c97e7a844a590965f58a142f192ca6378230fb13e7a1ef43d1b562123ebbf1c1108c5445a506394ed56157fcb38b85840aae3151fd66a" },
                { "pt-BR", "8fe26f2aae291b6e4fa25aa3fd9d62f2a59facd1d5304731426ff12ca4db345febb915ee31bd027d1d9909969d56b73941744a92f14cc726cc92600fd35901f4" },
                { "pt-PT", "3e2d3e45db2faf071bf5a3125643c92fa4db34b8cfa183ea1fddfb00fc2bb842ec342d15addf209fc20d28cbfa26ecf7f1456faf70520fa55c15e9c872133e33" },
                { "rm", "bdb95e8b17a2c803f2b8ee7f6054aeae5d858237888b56b8f4a1ab34e5bc639c13e6ef2728df70f50c1e922e91a722698309ffc298e3e800efde37f1561b3ae0" },
                { "ro", "2dae01e3bc2af5771b3a66616fc63dd22b702cd34f680a1d05b0e008576a53a0df8ddf0bac573e271114088f7b73fa1b7e1d758c028cea07031bd4e3bad72b8b" },
                { "ru", "e80764f74153cbec4efc70dc3049c77e78297ea02f765361ed89c07ca20642e050162301ceac3965eb58105eee1e88c261add400f63c10f5ee903fa36a60cc1c" },
                { "sat", "d0f37a4fda6e8ceb25419276613195945a668dd0d7fd11cd8f3ad6b6bab281bc69dfccb25d8a08a7ca470a05a640ce5daafa2aa4f93417e6d4b2e788609474d4" },
                { "sc", "92cfea6c12b1a2fea2e78479872cef4727e4d99f589e019bc3b31be7ecfb39c198abc6fda7b49be7ca8e81455792b20ed11516e7997d973fad624f3840098fcd" },
                { "sco", "c7df5c97a5853e378c2d18149ed4968f6b2a4959d519b1519314ec669f32b82afff45d4d3da6c4da261a80febd7861df2c63dbbb6d952f09710935e490a21e1b" },
                { "si", "b8e5373164b08b9093229e76870c64322fa4a4eff1156ea7f0a6cda505280fd55cff67c55d9e7e2cc4b1eebfa6914cd5328b6657071fc83d5704b3f4ae5a3773" },
                { "sk", "89802b2fcecd9e0ad8540e8b51365d2db21a659e283398bd30ec77a2b29236eee85952cc00ee8454b5d11444e46716466cf4cfccc5b77bb982917e3b30c0529c" },
                { "skr", "66d8255158677036699f22126aa68e2d62b2c1ff679d66cf7f4e85638611de260fc9556f71596ab2daad382f6a148545a9c12ece9845f80281c40287f153df22" },
                { "sl", "7805125fe24a7e6e0be4a8cfeac5794b5aef7216498fe903c952c30f067017c86c0ac148c2831f8749e081e6c2171b53814b679e019992323bdf82acd2839153" },
                { "son", "fa69027fef9da01993f44265f3e3f9653e1d436453d593ba426a1e4cd9e459e9c9b96ff5454093d0ece02f6d486745f2758a3e8bfb0c1dcc697a9c70a225ac37" },
                { "sq", "ff1f676b35d10b3404418ba81eeb94ad7404303bd5da0e4c623d055209f06821a1ac0dc81cc414fae4782ab04d79a5610bc5f96c7030446b88e6606db3421d8e" },
                { "sr", "8653715094cc073a947b1eed4494240e796d7482acd7b26c2b6c2adcaafbb2a03db9f2cb506d1a21f1b0b8aa6f9ede34779921a06d9cef64dbbd93f6ffde8ae2" },
                { "sv-SE", "22b428d9f3a394483442b3d5c9a775d72197485d99345bb07f8b34dff683685316c4e831927351733cca4dd7bf4be5af986e6a081471d02eea4da458ed289524" },
                { "szl", "6f99ff63ad59bd2bcaec34e66c9647459cd801e43e4de20175e705f980bdfab9bcd85bceb8768f9257ae29406c62de97be2511cb27f6d85389b35f89b0479b66" },
                { "ta", "9b774c5a86393b67a3df136ccd7c0dde0c4197dfdae164aa97dc6fd0e0671fdba30549ef6d216bf54e19924e7f304a201ff8446e52348d7f48443f195d87e71d" },
                { "te", "2aa66ead9b897b20aaf5f7d80e4a39a7dec9879a8e9b8cdf48727f40a43479a9f743313e83f7a8eae06c7bbccd3937175a8555f05c34b9f324c7c24b4cb256bb" },
                { "tg", "f4e740d27410d379467be153a4bb96fd5eb964a3109520b6c17618761eb040bbd9282ee4722739467b73ae390d4c5d91752cadb42be204286fea9f4ea3c82880" },
                { "th", "1ad204c79b7402c9d4deebfa1006de1ba35475cd1c704fa0d5791be825a787b550a97b4ed2bf437238935bc031fd1c967e6baec329ba6ed66b8397d21f3055ea" },
                { "tl", "0e3431b1a294afa0672bfba8464ef11c9f305783473520f4dcad7d7932cea5f458f7214aa9baa9169676794fca50f3d10f0a402980d6eda5a035d1f0ff56f2a2" },
                { "tr", "85343e60cb8bc24d986d7150476508e521008e32fcb32834f33cfee9e82689828a8a5472ac1e237cc65799311a77e624faa152562b1b1e85d0d1cf84cae40f34" },
                { "trs", "3befba3bdde120ad13e56c3f73930f94629fc442d786fe29c74cb03086b33cee2a647c6955acdabedc3bb1810071a0e3d47a9d27ecac5048a181f98c1e53cbd1" },
                { "uk", "a74ec8a570ea43e92cef4416750636e54bf7159e0d1d4e18cdcdd477b107b51858118cb9a14ab1587b5071380ad4eb7a7baacadfe86853bafd5b843b4acdd519" },
                { "ur", "87464514e5da8451e6e7e4ccf992366630a9ed825144cab59bef34ecd539a93750972e60b604dd5ea76a35501278d2dd2ac2bddff2962b67212ba44fc65ace63" },
                { "uz", "c36b9390ca21d46b3f616fbb58e3e192d6906480d6ebb92297c98aef0b116b23f5c661edf68a4666e5493ab009f12ba923281faeb9a2470798dd6e03ffbb4b88" },
                { "vi", "5182f64e2455efdcecc6770ca132cf4771ead3d54ae40de9ac5056f23fa98719790cc4d07b33ce2381112003fbfd4a08aa57ed9b24102f5ff67b2590561388f9" },
                { "xh", "d562081fcd2f53c97d56a44ca96ed02992156621b4f5c004d77b8b98a21cb3bcad279645c9e36eb339a1dc5631ebb65d941dc7f2e51c31da7cb5ae052cb4005d" },
                { "zh-CN", "fc4ca714a6533597faf297fdacd7a5f14d9ff41cf6359b148e8c6ec94921dbd6f8ad6807e04e77621199a4c6f03b9e79b45c174c882b539ffa59ec7d1e2675e7" },
                { "zh-TW", "88318e3ab3d4773605228b043a3d03b3e4a5d30d0370795a7ff0dd1df772cd7a311f9f00604eec73068d606e4987679a9de4636712abc471ef3b1672d90c13bc" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/134.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "9ece25a18defa616bf1bac2504446c6793e97ba5243f720b495f9d353f9b2a850fac31df9e01011578068c2635e8cf87367ce3eb06a9ec60af456cdb5b53a5fc" },
                { "af", "f18862beec923a00a5c2af712cb12d8c07c9c92e38bffdc8629ffe97d842a577780281d5ea0dc368367a78417a618043858a326dc8347327de35457da4fbef4a" },
                { "an", "f06896652cd1a3e5f50213906c075e0493b4e0e2c12fb2977ec3ff470956b55d2d0ddb616cec40fa42066a79b839677ae3cfbe3a658b49960a11be4d25c512b7" },
                { "ar", "64e973df7b80149c9c78958f22f4157270b813c38d33ca6bbc10f65a8f2ae8e8a9c4b29c9afb19bf5b04ea8abe09e467cd5d594dd02f0ad3f61393fd4783d181" },
                { "ast", "65091dd8ddf64eef8eee33d45acecaf54c34ac8252c3c9b4756b4ef8b412a548a8f12eb9da5c282b2831b1962fb73982fb90f0f751faebe9581930193154945c" },
                { "az", "a941a2a3419ac04af845c6a3c48025b7a4b88b8c86b757b471904c78630b8c6a3657c821dcf4ea7906ab140a63282ace120d62200fa0a46bdad328c4e0675f73" },
                { "be", "aac8975f098ad51312919a1b53046342bd68a1b3e29ef39d0db9375e1683a0f6600788047cd3878fc25356bf290a7314284268126564f89c22311e431e6d8066" },
                { "bg", "7b3434cc705aa1846f436942a95c4155441372c8b61785c81bd22f6f46531d7947a62cb64a93eea7ec1a964b57d27addfbce7892cda38b58e9d64fd9d5fe75b4" },
                { "bn", "b5c9b5ba1ecfa3551ca1375babb47478ea7737e56fafb48eef21f66c28babbb269765f0cab759eb4924c5cf1145486a6197e18ee4f70e2a828700ae111bccd3b" },
                { "br", "a1262c4033babac5753e08adfc14458cef8e45e8e6a5ec33502b7dd9cc2a6ca8f296200009e3167775887444a3049438a61c6c64faf09a7b05b671225982cf9e" },
                { "bs", "95fa4bbce4c9142520a31a18fba5e43fe414afc3b98212cd14996991bc29ed34d279a23d234dd34a5d54a4539019d67513323f108c8402ec293aa63b1998a1c2" },
                { "ca", "07253c6622cb4a955e552d12a3d80bcd8fd27e87c28f2f00aa995b3fded9d2e7f65941f0c0c04f7c64fcd70178700ef0f3b1ae43069030645fd43893f2840ee7" },
                { "cak", "254b12866bb0e7930e472627b4c701cb82d1a6c46ee71d60af2fb0e0343c1131cc4fbbac5265f571fa48b5a0216a6cc644463ae039b367d4a192e87e2b8dffe0" },
                { "cs", "e3172571ba0193343221d5063d001864dd3b2602dd2be471b909641d6ccedb014530750f6d5867babf989397c59c6573ceeb74468f90ec3f4774464c706fad2c" },
                { "cy", "49c39662bd47a64326d54f52a8d2c2ae2ff1f047df0fd3f6dc33cb9252038220fd60d67fccf7a53506da6672af337ae9757317c1cb2ef6b7021b070076780e45" },
                { "da", "31d90ef735657bc61421c54f9f5d43f26ac2d62f47e65e64654ff53648f4cf8a4dd634b6bcae45a1c53aab2ffc1263293d2a33f06e31b13fd88ab08abe1256c1" },
                { "de", "4d762b8ecb7d9e28caf6167e61d1b7fd5da243a38bc39181e9dec59bd5495a3cdc6fd844c0e4d6e77659f2292e3f55533642f3e323ce2f609ebae3ddc95c675c" },
                { "dsb", "a2be9897bec5b242fdf7c47c3861a6ea0472b2236024c960ed9d1bbc8525143554b37c25799763051426f05e8767d0d1d60ab196ee4423fe5cf918abb282c62e" },
                { "el", "67b1d6560111ae2e70652978d9f6cd4c9a985bb105c4faf98c9fda7040b13bc793e0cff482a797af9e9a938aec4432175e45a02ad4c8a3e748403dd7cbe97874" },
                { "en-CA", "b443aa2a5fcac2279c45f2a4d5084e9f538f05620da0daf8d43edb492eec6044426b72621ce19022e7ad7a005c33c196ddb0302248b69f99b7c90918f07f0e3f" },
                { "en-GB", "625f16fd66b482c5bb3310bde737957d6e7e724b950c8faae7888598045b916c55efc043eb35cb119e5e4085dabbedc2c08ed07ab6a9a2cd6c8e7d70cb18449a" },
                { "en-US", "90c202ca27bfdcec6d28faaab863e157a774525d3736c66c4eacecb7dbe84926fcfcaaddb2908edb857a0e6cb497f4ff3da061abdbd296b408873c62457d95a1" },
                { "eo", "1a9652fb4324de8fda39891c7367d0f627057c3f97597b41671451699c56acca553f9470342f6a1bbeb7d804e2660d6e55bf4f588751b29e1d10a1dce96e28da" },
                { "es-AR", "713088a78c4d0709498a9322f85f2e0ae1e960ff9d961cd32539d253620a438183e5877911b8f0d9cd84bdd044fcddd9206ee2db707519fa623d64b5d2e7ac90" },
                { "es-CL", "08b084cd2b435600b5e740bc15a4992b7e2655be7bb41177b3048f35a5a15ec233dbf7c7e3b1995b4b018117cf2a69acd66d79a12b8a45e44e43c1cd82f01841" },
                { "es-ES", "c93aa6577e3f5da588dad91d0013cddc0785b714a4bc8ebbd87a34e3ebcad3ba7bc31ed53fcf4680d6064bf541e30df023dda3926c3b840f83ebad4c1708b3d0" },
                { "es-MX", "f994a81ac0fa83a03014cb37a961c28e8607f9f738ca4c57232cf92dd1e9fffd75910d95d2a497aacd499d9abeb7350754d83c61c833a82ff8667a00554ac278" },
                { "et", "ba8b535ccd15e697cd3dd8a43a8ed4aa38f25894a240cf4c6776e87d1adea10e32f0d9121b4efb57810882a226a9b00cdc3946a68ac5a43b0131eca4bc574a18" },
                { "eu", "f491da146e5a12956a074308dfe1352b8c16e625d5446b40acda2169718d36dc4dfba84b3db9bfd02453dead3907fda84bf04ca5cb910390f1d2bf5a6750011d" },
                { "fa", "2e659552c477ece8e6831c1518d9863bb52faa0d86e8aca73aeccbd73953db132332b6c22502537f3b61cf05bd0fe8e3e00b699e94e6135938f905cc5cfb2176" },
                { "ff", "736a639bd852cc6008a982cfee5654150002844bb22694177d0ebaf7f747d016751dbe7a3d245cf490c2119c722d1bdf248c2cb595a9555b01dfe00d0aed5ce1" },
                { "fi", "c74f9e15bc8d155266b3d062aa417016a27d51626bbebfa1bfd3f0b1e3524b662a6f8812c091bfafadde55a8e224c7c92774a6ed3c1e42d29a987c4f1035e420" },
                { "fr", "c3bfe73bba34ef796ec36ed5feee8eb912f8dc6a43ace2d9294167a4d220dd18e28e865f911384e44d23a0a94f67292007ea2707fac4dac5853830d7708ade67" },
                { "fur", "a779981b286b027a00013048df8b47beba03165c2716a723806858ca9b1b6d91cc3ab94f0f0ad4d8e999ac542dae7c0b85664181e083554b39a21f6cab6f0c7c" },
                { "fy-NL", "0f1c667aefb2fb2385a05c5e79c69c7bb9c665099129a19eac1c9c1cd8a3a6ef1956f6f52bb50c7e94967db034c76d830894bc247a04d7d1b5d5f2c4f808a2de" },
                { "ga-IE", "ad146882beffe70e0068f3d8237050d0988b66ad1bc219b68bd2d61703b2b434a390f3271fda20e629747024c5bd44f78f1be3c8a74b507e132a61133ab1d963" },
                { "gd", "76f9ea87bc744852b6b9e021478e6a088bcdb5f97bb3e3888528540f94c6988b491e15d051a62146472faed0ccf66fe75d9c85e87dc3c388dab354e476cf136f" },
                { "gl", "1d84134bbd59fc71e660b295a2ae72de20f0cb08324ad2f3a73b6320d6f0c6ce97662ce888bf44b61a018c9cf6ad0db7cf9e4ff0d1a9523c834afc5285d9feff" },
                { "gn", "4319743ba67bf0def9297a67786f7aad9412553c0a9283d4b0941ee66eae18c2a22d823643996935f361dee387d7b1e3e1a981847e4f06a27cc028c0f0a9f3c7" },
                { "gu-IN", "dc196e88dd1917195c169d32b1775b13750a66b2422aa6bc3039c291f58b038491ea85f1965764c64e7522f7539da8a6e9009c95c2eea6c23000db5c991d0c0e" },
                { "he", "e9948df31f0dad731e1e0826d4d6538e7e2ceba5244de77c61f3c089cb3ebdbbc3e617fb91026505086f9ab658a30612f1f97ddc7b4c0217e274fb74a35f7606" },
                { "hi-IN", "8d8685bdd7c3c88d707988a52dc488d58f006e92ce55a5d8b72199fc3cbb55d7b1f7cfbaaab9581f5bb6e0be8d87bcb5e10fbb72913171879b87ff9a2836d65f" },
                { "hr", "c15fd6d746fad767b18d390da6066f57ac09b5b923fed34ddec4344ca3c198ce98a8017922ecbf5145f434b689a7b1d369967324c6aaf46c2234e6ddbee77282" },
                { "hsb", "bcef42a7014e6a8d192701313b2e665c716574ddad96bd9defe61ee9dce9e8475350346508a0dcf631a16cb9273de2095405912963a19a4262ce3aa5268167cf" },
                { "hu", "dfdb2931a57e4386ef9b2ecca8af0ab4714a6adfa9b482da153c411ea90576bbdfe74c65f8432850a9a478ec3df8cb1151dff22366a7faad08ac90e79cd25412" },
                { "hy-AM", "5bb28c7d5db920914c8c5f184b2a18bed123a1a5f3b96812688200d5d012d680e2076277e9788d89c83e237f397e75604abd691d1c1de4f907000d257074d45a" },
                { "ia", "53a3b4cff558f89b59f76599fdc48fd975496ef1374f13a0fccfd9d2f4acaf966bc586da1cd31dddb9f733d8a9d802f86d42e746aa5ccab02e1c04a9a7c1f8e9" },
                { "id", "075b3e0e528a62a2f9e739beb2ee636392aa560bad820ddd5e6e4f715fcf83ad59fb841f93596022a8ee164398d1969b1c101e3449c9363eb9ce3529bf70d977" },
                { "is", "e927bde85e94528162127334b33471e5ed62ba2da98801e3a5d3293dbd72bf25c503d13b6d96e095211d28950c85a849bf90a2264737c56d449cf817572655dd" },
                { "it", "6075edeaba153053618918d622a8e469f5179d94df71d4219024c7d2f3bcc3d15cb25d195aea7a07cd2a84c3e38e313715140cbd96a6c2158a16674ef802f7cf" },
                { "ja", "0434dba35023d19d4be6c2e04d65ab20a0d61cde6d0b2b7ba4ff139da55c55d5a704669d6121b236cda61401d6becbb033d5742c8c5ef592f2b972b16499d852" },
                { "ka", "30eff31c0b185b0481b226a0c31e0f6e533cacf51365b95d4199c8232646537c2081891d48853435d114c7ddd9117d51957b1429359dc6a45a710ef23d09334f" },
                { "kab", "3f3d1c5413923f709bb80d034ca22ed74439ce7f51a8a4fd4e2aa2ebc408e6edf3b85ebaad164b4ac53725b62e29a02a2d1883a47d54244f3036f77a7aa97260" },
                { "kk", "f98ff17b8276e3f3637c2dca2d58f905b3d23c36010ccda79e05786bc573ab8fc34920a1d3a14739d0ff4dd73f87024a3d6da8991cf4e29029c309af466c363a" },
                { "km", "d5ee524685ad4f82e88df45d9863f2d1dbc3a96c33823f49c95dbb7d85d6890a4e4bc1b4cffae0e660f1334765ec11346d56225f402c7e0636fbd61992c69cc0" },
                { "kn", "28fe936451839ca71b0879d7795bfb8bb616a902dde2f5f82389dc9932b62b1612cf37994d5671a832c85957e8ad6248e904b5d01c0cc44fbe36c3f30655a115" },
                { "ko", "a829ad57c6de83335882cc5f438fdda3b032eba1065cbf783055380a017571a7ccd55e112b2e1f218d5c7d32f4b64a8d7dcc304c0a54d9162433627a3d160e0b" },
                { "lij", "220eb73cfcde8992e7b17c56eeb8c9023c713b7b6f9cc566e740b977342540062b4282c8e59c95cbee2d953614288e3dad64fefdd462ef415a4a283a2285d000" },
                { "lt", "b9da4536862af70d13c6661a146786b102479cec422f3074a5da796a4c1d7a71149145fb7e6b162a65fe9eb053261a431167564036f3903c8c5b9d3304334d7c" },
                { "lv", "a2a053b168d1320c0eaf682581de8908eedcdc65957ba22eaa8730d3251d3ff06c029b8bd7dec0c44beb393507b9286fb70ae096f88da918a6714e5e146f9886" },
                { "mk", "406da71f50e96a024b636f29593c1ea63a4f08ea5de1db5e02219ee8cfe43a8eaf8c36adfae0d90dbdd74f5dc1c0803823ea5879f5f6f018412d2ca9a401453f" },
                { "mr", "f826cff77f70f14df7edf2890e0b9bba335dac705d7c29e88304cc121a12f7a7ae6ae7536a373275599b417aa977a12e46a48c31e248bcde219376ee9881066a" },
                { "ms", "2b81a8d254b30830dcbb8c088019cc90aa86b26bee0c3f571b96a4dd50eb216c950bd61eaea71623a59b6b76a19b484f6c8959cd4a69b300938c94e39f651424" },
                { "my", "d4fbaead8aab27ff0214e9946c584484f2eba61dd240cec05f43bb079601f2f982324a7df65e3c7bd932e98051e8ce7e399f23620f32114a2fe11f71495284e2" },
                { "nb-NO", "41d723eee206e57e83a311ec8111c0af37445cac513f57f448a9bdf1bfecbbe1b9c6daf4747f4a7fa38deca8249de244e06fc10cba9a43c8366a6d10e7cac176" },
                { "ne-NP", "b2c09d006726527ff29c0c506a9b0911286eb2fd1c115322d5c33962f5dbc0c9dc84c5f62ad9f9a2af2b69316dde7992bcd0ea34a400a9ff510b33eab32a4f39" },
                { "nl", "b12136e9298bbbebdc9df9df52f76a3fbdad89bcc612206caf50958cff5b5dc70a7d7200b1df28a803a90ac1decaff890a4c4677b7b932ee628b142a6b4a7314" },
                { "nn-NO", "2f43e8ffcf0aec724c9606eb69a6345b1e47ba9176d0f97715eb1a2745bb8189e00a203924805b02f37b63ae91ea6de6b5910b7863532c6348efa131d958ab09" },
                { "oc", "87d339113532f04ee4c82ee42f2d4cb854067acbd58c7e266780ca8b00f74f1953067bef93aef3af9423124d9c8e57bab33cd91f145a2026bb4870454aebfe6e" },
                { "pa-IN", "69e4706973e68b4b458fdc335c3bf203923987aaefae99a7284edd245b8b6ba7fe282a665d3b98245436b6f7044eae1bb7966f2bcd16390e773fada60391b124" },
                { "pl", "f3b1f3a39f21420bf40a29a864e8b09013ac4af2149265cc330c0a99ed8fbe963c70630a3e5f0c0246208a6058779d2b1f0e28fef46d26f1d386398459b2e76d" },
                { "pt-BR", "0322680aaecdf40595835f7fb03f02b69e51e77e987eaf3de4cb9f048723086f333066e6ba3221c2ca56d761355cb1bb890263dbd111fb5099f0a1a2d9bd0736" },
                { "pt-PT", "72fccef80d2ce1845dfb6e0bf67c73aa24bfac5fdbabeec7df64f5c76c15fe403ec8495d5ef7e8d63a548e508f922197611b609ec8996d70e1f708080b159d27" },
                { "rm", "ea8583630872defe691f66aeb0bae537746270db7ccc9f5adcf28e0b14d96fa65c7d78b6c8f0b93133b29deec35f7fd4574f6ef338a8a5ac9213d0ffe57b92ca" },
                { "ro", "e73f1fbe83de2ac8bed610c74a672b0b9dba6e54e312039d549e6f036449eb856a4f646493e0b5bf3172390e4d24ca5eb1e850d48052d4a52b353a3e9da6fd94" },
                { "ru", "ce2bbe4b8e48f6111f27cc48d8dcf31f7733411c38ef33918b805219a6308c370d2c586e7b85df52e278c0bac9c08fe1063499433a074aaab8a43280c51a5769" },
                { "sat", "4fab6ad217d0df5fc0e3effea2e474852bcad3c046f9cbfdde908b202f088bb0900089ba14b33bcda4a3295f2206f32e688e02b4c0cc25e52a67634758ba0872" },
                { "sc", "6887698b2f9fcb81a8af3a5445af54c51da26b6851949c7cdc8cfdea9cf66e8ec531615d1e6d8ddd3a67b97c5e62c79a1c5ebed561ff3cc93f79045b1d6e0535" },
                { "sco", "6df0a3fb520f8d53cd736f3259f3a612e82630b33e1492af3f2058bac12adf2403595c879ff7dd56e63c10c1d5de1460f4af8f042daf65706ac767a823d445f8" },
                { "si", "2ff3fc37891bc7222353bcc26c42587b2ef168b447e04ca84c097b3608604b1fba14fb021613f1fa199cff91f38b9a6543aeda6fcafb49356ff8f5e2f2784b58" },
                { "sk", "48c353905fd30ee2ad563bd5d686eacd390b0b068e3384cd2f11f26e762ce38757f53ca99849f4cd554ee40d217b6a1f740cb9241952a29ce77477192a1663d5" },
                { "skr", "a168f224ad046452a944742d7856bbaf93e19165b3db6eac118897b1a23aede22e516ac36897d3f6df2f0f8044d35f72a43e3311d1ffe2477bf55adbc6d72c5f" },
                { "sl", "d1f47b8ebf8c093c17b2a66b9d7929ed95a0a7f4481f3312866dcd560b2fe0120aa3b31a82a6f760847c4bb992d81fdd056cf7c19a6fcf6c309a13027978895c" },
                { "son", "84cb18530e5edafdc030aa24a87e079be0df14799058398380e223554ec009be3d46876cb80408a502d9d689ae0c2c9cab2c9df2820d8ae32ba892590e4bf000" },
                { "sq", "f6c51715bbfa173de9b98ea725754ac04469faf5b9c375c66f06e540b6bd15fa1791bbb5a04b091689a448b0ab1c0c64a82e5e616be3ccf3ccd72973e0afd9cc" },
                { "sr", "fd2506f754460dfa63faecf93abdb9fd6c3843dbe2721f0864ff28c29ad737ed6002fd46d2e9d472af2654a9d10c967aeca656ee8ad8f7d38ada0e9a02cf29a7" },
                { "sv-SE", "9d5a10fc3278fdf31993d0294ae71d4c5c8098f7fe76e2b04ea1223f5d5f45aaa268ca8153e68d190d3f6e8183bad777f54e8a19c8f15ea9f0ef07c3c7ab3d28" },
                { "szl", "c128921e6e48b7ba74fc8e573ca1252482ce805c60c38d7d51a60c9cc1dfd2381a3c39d45fefbded8b278fb7752c506ea15e7a8ad0cbfb409f187ae3c4a0708c" },
                { "ta", "3d868752d8c3ec8411319ee9dbf307d78abfd1fb11cbc7f6c7c92d3e91c71544e5b7eefc15640c5ad0716779d6e7b3b33bcdd81485e9ae79ea3e175d70721f69" },
                { "te", "17c65197e675024acda04a03f93cedc8e284386dab630bd314ef08fa2d4106945c17e7e10990a2baf4a2a9010b90c1ea9272ca224585321e08a8cf5dff27e52f" },
                { "tg", "3f156f09077a5558d309e50a61261feadb57f36b9a81e61deb5ca06556fe787f1a4dd392c454e01aaeb6994cd4d4b03be2c9571b1a04583d1841c3a8573d6c01" },
                { "th", "c2fb3362b55b6954addb1c5c61c7f49dc476ec90b4db21ba1ac083a8de35ed9c2ee8f8f985e7a604d48f9fca66bf32ed52b813d17e1fccdb8b1121cf02bdc868" },
                { "tl", "a9dc85c0cfac690063682a3056ba139882e03cc492df11a3655d74af9d2fc29caba8cbc9ec77e9486bedb46801558e0c429ae1f1d41233f968acb957c01e87a1" },
                { "tr", "f36589291f3fa5878b51d28f36bb100026a8a1e1235fcf15eb5689ebe7aee206bfacef5907e3090a7883e7cba9fb0936d4a97aa5e3166894fdf69260a43abdcc" },
                { "trs", "0a1bdfe826bc2903b7d2d47c83fc70135b1ce2e566159a07a09d22b34e2333420fbafeba3e5ed1130145c8aca961783fd99bca82b2856201ddf307915b4425b4" },
                { "uk", "4dfc7e4a9a5a3e37971e6d8ffc130af94fb20680c20938dc60f854fae8d8c61c0e622d867b437543ee53f2b5fb58ba35d21e2fb715620dac4b1614b2d36e0f3b" },
                { "ur", "261c9ab7a1cd73600cefbd55307a4ca075c9fa97b957bde211a92728b7de134a0dab252e0d891f431cdcc0e7d76d41ac6eb2651fc188d8591334f31b62b35cd9" },
                { "uz", "62031646d6530e0169d099d1d3a622d706b3b35819a5c2232192a4c2739857a0cb139e97ad8ab50698a61e673cd16a419ebb5297a21d299f6c8435ed67b0b604" },
                { "vi", "a8a002a02d2aa62cf17b9300efbb93ea6c1d02ee6aba96125f6af9329fa6112fe82dee8f4d4ea996e083e201a7e70a49f25b66e94b9f46c3ddfdd54f0454401c" },
                { "xh", "228440e3b846c2c4e80102e79214e47344aad1f219135286baf06a806b330c10ceed6e50cc0f30969866a1f9d6558c6b6fc0bc6422c66c95e0a8f0f734cadb88" },
                { "zh-CN", "4e98d0b7ff65d5ec5b7b117d9d24ce55364b155c05769a142f35d56d432249e00faa8410800be4c289f2d3ff4331036ef5967588cdd043f4a56739b03b74baf2" },
                { "zh-TW", "dcadb84b82ad4cc82a629dfc40586979a30214fd19c833c1789785aa771bede33df81589b9bbf6e667890ab6bed7e3591557c90a25a5e040363766d117768c27" }
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
