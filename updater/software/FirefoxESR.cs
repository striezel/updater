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
        private const string knownVersion = "128.4.0";


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
            // https://ftp.mozilla.org/pub/firefox/releases/128.4.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "fb9cc6cbe76ea917bb313a6a01c550330c7e6b709a47d00c6832303d452fe53fbefca0cc45bf878b2f9d46b9a2e520b76c70cb44d8c45068aba50c18525cf62b" },
                { "af", "c1a7f2439cd024af99f8afa56a1e1ecbefb368fc3ce67a81b6e31774983906aa58f764458624c47dadc2b97952f907634c000ab5e34c281eb36cee476dec9a36" },
                { "an", "5967e6e3728516ba554a1bfc4eaa78496b2fe481b3c60908d841ccec4cd3b049afa30b8c97a64b92913bf816d8317f389c9b362493ea8faf36e33f4b97348f69" },
                { "ar", "e320ecf40fa0a6f510892c630a04ea71d91121763ccae405ac629e668a72c8f137ed88c3f8b61f2ba6bc18faadba8a0c54d3cf83c2b3c1d4b67bd73d501a2842" },
                { "ast", "ff266f49a9eeff0c7a9e94ca3e61f7a667d710bc9415604f41e18751636c49ca6c94a40c6fa411826401e60d89d77008af08c922e33494202bc5e804ac326243" },
                { "az", "eb0b8651d9645df709ccb28ae3082bfd63fc7263c882b4307f3d06f1c1ce16dbad47f1355cdbcb3165fbab2688b8ee2e140a1d2ee3441ee7aa9277dee143e1cd" },
                { "be", "64cba6a4e9f60843c30458f6a2f7416c1b4ece43a6f98fe24eba5f65057df3ba2f8f0b270ff531dfa9901b8a3ca17b873bad965b8a293a656a6c3ca35401cc2d" },
                { "bg", "5f62ece0d2c1d7ff43a45e00c612373c323ec5bb5e4fd6c67dafd779bec3a5c7a75773bc9c22d9259a80540daafee832ad338e8bd58b80d8e73a63bd5795b675" },
                { "bn", "b84ad5adbe26630345f724719fd72159a08327e79d3f6c1dfcfb6686814517c21acba86c9fcfdfca167fc02f0074fd652b8645d76dc1628f810465b8c83bc28e" },
                { "br", "7caad4e757226e9df815f0e35feae464c36d6842c7d0582e2d508111d8c8c7e805ab65c32c6c907866bcc4f76e248538d01a54265ae93206fbc7652ca083f6c9" },
                { "bs", "b61ffa3b210ceb9d85bbc8dc3833c98ab4a1594b6d29c58a3e9b97bfaa8dbb57f92dd1a06e72e7a0802eb150dd4fb7d2897ebcb6bebe2ca950b5008344aefb0e" },
                { "ca", "75d5611a3caaa12f60710c6d7409086188d4bcda86e69edc379fa6d9f86a4656a963f3ab7eef6e89f3b81b8fa492a6c89f40eb35d448c15e518864acd4089cd9" },
                { "cak", "b830bdaec16d337dcc499e53bbb8aeea71d4c8f7ed2cb35e0ce9c96174530de3293c8b9e52939e013278de6855a0f389718080388f748af0a4233d4df16973d4" },
                { "cs", "a7c9739920920d537e30aa23dd5339840a360fb50fa801c4e588fc1eb251e52915ecbd5c9dc62110d3f3857b0e08b8ffdea4172ab0717bcb8a066ee809984bf8" },
                { "cy", "1945c8b7d3af8a35990e542f7fe4aed638d91e2e2ce9a68db2019be2c15fc3ff934e6035c5e8f6d25629154b4e3cfad7564cc1f2fc64b718b6bbd44202952010" },
                { "da", "c0487c795e8433e0c5c6201ddb8ab34a2a82a02490dbc20ab0a520d05589508fc3693b8d1bf73ba2684081fcb2b2a41307abb1c6667b631af68d9797a652865c" },
                { "de", "454c6dd9b7dd0039f747efb5352c55b27b3df0a437f0230ef3a46e57efb4b497926bc6c41e4af5055968ba77cb320a805f1978466ee8a6d105259721bcc29ea7" },
                { "dsb", "b428c7cd263fe4e99bac34bf1754318ab6b8eed11e0b5bae2de59a55c1809ebaa3dbec818e44e82e52a0647efe35a2e86b8e31b5060a3d1a1aed264b14ab4a7c" },
                { "el", "75929c09f7142fdb9522df5f126a6fc4ae0114265b95785ed364827a3d701a18c60711753305d02814b0b8084bbb3b61f4bf02bbe3eb81e58c51be3b4b84be86" },
                { "en-CA", "1b53eec055a1eda0468360f050dbcb891a313c597716c43bd58f844489f2a5eaed5cb80c27f1a21175adbe4d844d71650f4a557b7ad334146119571ba3cd4391" },
                { "en-GB", "18c65b1506e47480c0a487520a2a793cd0f283480029e2cf58607c497f4c9664b480edd4946c6a6aa0ab2979cf2218d9362c37d3c7f55f63095fb1d1cd4f0446" },
                { "en-US", "aa4286afb5cb5054f963fca9e1f19bab682525225f10f2ba2f27162bd47b5a0edd05f183fbf599f38bbe33607e9e3866335010ce23c3ce3c32d6aa365651f298" },
                { "eo", "c0b8b21a1c7aea891a9bea371d50459fef44084f819ff7b958e4b1776c14e665b0e81f56aa7bdce79e603626cb454e45b27a2822188bdd03b7c9e47a4b5aa2be" },
                { "es-AR", "181a2d73402bee92944ff6d7dae1dc0b4c829ed0ae8651b85caeddcf445ab9dda2d2834559ac68469ac32060d7f41dd707e7874b12f0890a7172b0cfb04cd77e" },
                { "es-CL", "351cca5f2ef9c23321e718aa32a209a7e06e80ae06c4b05047f8d08b599a22b658e6f4cef218dd02a9e1fd493983234fc5dd5301cbd146deb1491f8e87ba0b87" },
                { "es-ES", "1bbe576f7a4b07285a7403829d19fb8dc1ab615be6f841b8b32222a811b6db5624fb96a75ff74c31ca67aa56f7c4fcf2b780269b0ebd332a68333578c4a98c1f" },
                { "es-MX", "77f815ee8dfc694a255991907e5c300ed169151a091c0fb12c579c20f0721728c645aae71906f3078fd0c95353eb66b7075fbfcc47fdeb9ba1a3bec0253bbcb5" },
                { "et", "1bcf1ebb31732ce82bc066f415ba5f81312701c985c956a70b35a8675ed3905579d4f6942c149ad8814397b9a1ca38230f030500873cad9afd1849cb0b855df3" },
                { "eu", "ba6976097155efbe92beb723b7c374f79f2f3cbb0c9ed11137ac22ba0bc5184fafdf8cba14839c0b876e18a25d42ead3c0c4f47220479bd73a5fba68e0bdd7a1" },
                { "fa", "2e598f9fc837ba550c22249b28bad27ceca8e53ce95f3d6fc1f249eae527c71d353523c9059e536053c105784d3bbf69c081ff4cb0eb5bde882702dd5efc5659" },
                { "ff", "90b1385aae6d5b6706c5ce393d1620192d588cf8769e192851d441d32d862128f3ce12018c4b524b3387b5964836db07d4d074e30049e41ec72a94cad46c25af" },
                { "fi", "9bd2e2b52bd9aa7289a38eae363959a82589cf98c30e75412e5e20ca3e6fd27fc7c3bdf87a81c9d7e8f96076df424084715b55cee4ed42ff75026b654d1965ea" },
                { "fr", "6a02ca59e3f32f324709efa1271b5e86dcb438b283c1e44e5e0ff080a03afe69ee47445a583978079fdf0921234fa008573cc6b9eb24b67121550c9e2099af9d" },
                { "fur", "bbd79f623464b716adb2dff91aa3317336c9181cd49f8e0ffefadf0d90111b2947682b471cdc0c74d31d8cb9f2b3d622b91128d2bde4e36951b359819f2fe2c6" },
                { "fy-NL", "e21a50ad5e6f09c092e9439c4dfbba6ccf165f235f17604edbf0b7f794c90e4437b556e7378161ac3b19ce52e52540ca410a4c3e290403be8400336e9280d15f" },
                { "ga-IE", "46bc07e0b9ca351d3ea0bab353fda70b5575db21e7c88670a617854653ea97e8eab9b36b41a35c65bbc95c96b3e9173fa0aefca100bd361cb2db16000115cd89" },
                { "gd", "381e0cfeff7bb94e7ab4312aea5d19b31e13a97ec096118b394fc7fa3752e90d40aaa9d31f52731fcf7a966167ce7b9fb703bb4b18268baa5c11ec3fe9147cd2" },
                { "gl", "070b2317e14aa50fd2bed97b9c6b2a4010fd96a08945a5c25d3cc53f527bf93809c7c67a10ce10b1ae48e917d47456e96f70d3c346c016b9929ed47b9024eaac" },
                { "gn", "fc8a9be22a83a096597b5f5ad53c67afde8567b11209ff4559681cba74aa15420bb28d3866ef23aa1cea9a211910f88cffcf02082cbb484f0d567fad04b6f121" },
                { "gu-IN", "2d363d1dfd24c3c3047e8a9a39b6f9ff8911ac0cb04cc634e641707622f01d1f8d674a17ac4020aa1b0360cac4511e708e9a85dc3ffee06f5c2683a505c6acb4" },
                { "he", "c7269e22c4561202fabd4117de0dc9c1995b2afb909a32499b79dea2e0fe0315992bf76f6cf2e088f2fd8b69c5f1d9fa1e91889d92f64c459d08c7ca91335cee" },
                { "hi-IN", "a543eb624be21ca58c05d5c09340f05798d4ab781ef1771e0f537a850a0660614bf6e6b6ec99c936d14da132f518d32c05b2036f9c4030d5da52ccf816e68fd6" },
                { "hr", "e0fc42dcaa5ebaa2b63740435f12555492a770bb6ff1a8bdf1d446283cb1546d80be89c9e30481c234da0da2c43320feacce6be86472b17f225b3b6e9c441357" },
                { "hsb", "aa7beab4d5919e88b5c8307ce2e3bacc5239f434e4487cf764216222667fa2191c0497949a6f7cee2ea03a06c2cb81a2d39dcf9299fc00b79200f44c9bc5c507" },
                { "hu", "2431d7f3421dbe40647fb85c1823176b529cf4dca3882b26cced0fec3d0de665655dfedcafe8640528a0595b3f6ef4c5b43599f148a5958660fa992122ba82c4" },
                { "hy-AM", "cb8f55ea17cd829ddb05fda67191f1226c1e97b525e3b2f2f2cb4bb9fa0cb0c77a0e4f33f6ca4ee48f52dd40bbb79ef2d0aa70afecf7a5ce21ae200455716e0a" },
                { "ia", "88f7bf72c5c1e6c741b1e5b273122bf5c8ba64aaa87a793b00ead14c598059066939e33940aef4373cdf4e626193f96f77b64d71b9a2362fd97e632fc42ec8c4" },
                { "id", "03ef5ac075b1f9b917bea8567a8f35257fa7abe9c67c4e8590246f742cb8a029de2e4aa677512336e2cf0b7cfa87ba25773b1349be5da74b083b86ada4bf7b94" },
                { "is", "292fc40464cbda75ef9022c25cbda4663733daf2c9bc8df2177d60b25f31aa4dccbef7bdc188cda0a178e754d0721abdeb5295e5d937f24dbecb3a0164782da7" },
                { "it", "1e86dab3dddf98f36a7032c0cbca0c47d9f5ba4953e792e14ca34acfada6c5db901b6777c85ee3e62ce72ff26498cc61acea8c5158208f8fa3673c48afd45836" },
                { "ja", "ae2a19005e55714299ed80d4045f48c2d6f2cd2dbfcf86ebb5208043fa2ff90b236cbf8145825d416b346e35ca03549a3190f98443abd5fc2899d342771fc63d" },
                { "ka", "8d91212dfdc5bdd77f6b86e67896348b206a3867806e5788c4f8bbc3a889e98785829b37c4dd8fa93d2d4512446d9b7c0b63e526ecb87f58c6a42b56e2ed69bf" },
                { "kab", "9d8e7523ef6fe831d2c4cac0f8203515401fdb3891ea8600c610fb6a4065e0b8d6a7c9a70064688b65b11315c222889156178c7148097dfe465231f4e0aa9081" },
                { "kk", "b653a38a52298509eb393e6c49527fe81587182f6c7209f7137765383d89cd0672921302b9531989b6e4d9e80031b5b2cc9368f2ee0d28e7ac0039e3518b75ac" },
                { "km", "1fa4b7aa3db07cab3e27a128cc94edf75a1aa868f96493646d9e7a1fe40ae06ccc3dd7c6ecc8448d2d8546999f6a693035b3c71cdedb5f5082d110b38f80e2b6" },
                { "kn", "0510357d3a5ce91f6e447e9a0a22af21e1e77a2b5dc1a116db0a955fa113705f8a14c81efbc5d5b86ed5c7080ff4f157afdd061b16dd80742c07268f45a7f5b0" },
                { "ko", "a28a1f50bc2aa009747323c42d0d90f7cdc646660de58340e3c8e2e2380400b91702379fa632fcdb7d42b25388af8c4c248f5183af820b5b595e797c0fb20c15" },
                { "lij", "11256b383a110d5f4dfc44b2b0bce2db2c262681168aad5b1650933b3e2fcd1e3adda86c367d727d84af24649039a76d025816d4a0e9bab4a4833b1af69ff2db" },
                { "lt", "d5a783d61b87709157e3a8758ffdbd3d286bd3bd0ff1aa6ebaad254eb2336937a4134f55f44ede179d449c0b31c7312afc362aa0cd9777e8590cfe75e1db0a43" },
                { "lv", "3e303de5cad93a6458d7facaaee92e66023270ad0bd8aa115888cf2fc58d3a1948bd2de805030def49748e41cd939c19a6dd625ef04b8f364f832cda1885a084" },
                { "mk", "7ad4d1b4b22c51bc35e932333e99989d360ea3ef26b6901f4f059c83f0a11f241c3ae45fe7c49f0307fc2988e8591628108647247616a7483e54253f58c86ed3" },
                { "mr", "fb478a6536221dd8660b9f9acb94537f183fd7bb408d9103afef28773b9270c7ecec2fe622a60919b6293ea207546a6de0efe9e46363c43787caf10da24fd193" },
                { "ms", "71c7d242a4e257734ef447f9857d5cfb662a4c7ace146519b24015b11d399e00c7ec91f4de460f6568043cfce8113947c5d8776f8510534c63aa01ab03fa6823" },
                { "my", "dd1146a2598c18d2e67494a6f2fe287606dc4642161122f8b70005cd257004afe9ffa851b4d1fb6f1a42e688dc3deb3b158b9664fa6e879bd4efcde2a4676158" },
                { "nb-NO", "43472199fe12ad18509371daa235e6fc082fa8a34d42ef8f46215419b814ca2a33e15829a02f4c4e888de9acf88dba50cdeb7ee8404ecad59c1914f17bb61f91" },
                { "ne-NP", "183abc85927b9996f3e14f13c2eaee38c2e864c55ed7f23f73b8e56af2fdb8143a1b725d0aa81b6e937f7bfb32617595ab19796a97ee5f41eead0b5437b9ee06" },
                { "nl", "7347fe22590fd500e267a1138ecc661916a4aa161f91b4cb11e7592c4601f5a6e03058b8194278d6d934aebaedb8830850a3338a3d9475a42e53e14b8a8f40b7" },
                { "nn-NO", "1a2d6f1fc7fa6c471c08fab0a0a6cec1e74b17fffbb61f95d10f1d457877b0d66f68d851bdc28479557e94afae811be6786c5e064de72828d9a10ef6b6b2e99d" },
                { "oc", "a84d1ea3d221373db00bd60915f1aef06f6a7fec4f4cd5ce55fa16e37e64ecaeef330d027ba4265be72b3618cb7cad4353d8b38db5f481c84f312728250cd1cb" },
                { "pa-IN", "db8e99a95adf08dfdc21d98d69f2ce372a3557b70fe89e0be4203bbf15bddb235ca7a50461304e6365248ff7cc7a0abf7c439ed12f1392637e26c0a3580a8a4a" },
                { "pl", "3fe3ce99a6c415be7af9aa22a2169fbb370a487cbbc933c29559b6260e6fab23c4208921b8744d5b2e3fcdde457b72f0a1de8b071593d5553ac0273940bf2954" },
                { "pt-BR", "06a642f1fe36eacaf63205c7951cb81148f747395eaf620e280aaa31c42a88b20eeab0444fca292bb394e52c40f65d8b065ca096a3de12dc45f66a88e5792ad0" },
                { "pt-PT", "e14a74c6d16dc1e6a398789cadf1dc5a634660fe25b7f51596f941d7eef07343337bef931d02d373189e1c18a1d089d5ad6f5dcd47eac5300b3af8e314075ad6" },
                { "rm", "777aa1eb40e308f198daacc93077464dacff0e87d67db5562c8a1aa22203de6fdee1b8e11c8da452494ed84bbf2db7cf0d76a3727b2ab1b5146d05772546de28" },
                { "ro", "23c28ae01f9dd1586c9d92b3f9999bf6f22e59efa5a2edba581c24134af87728b266872504b1a9797642e6181b36d67ec4fbb3747cacdc97a17c3edc7e16aeb0" },
                { "ru", "41ac2cd4fa3640bd05d3c4d5db2b827efa15aa3c3f5cfa1f07ae61f5fb83fe5f460d408666f666b07d84e057f251a05c9f979da9d50b21d757589d92d1a936da" },
                { "sat", "2ef91a4071e24cba7a241d5a1797f4aef94c6a6c94887df18e1fdf8f4f1987061fa6c5e23d4f583590be921f38cbad61d03a053b0fb21bd6a2599dc929472935" },
                { "sc", "f9d4726f577dcb87cf91749c02ad5d0223d3063c56420473e7080cd34f5856c5a50e28b4835e96f5f7c2e7ee678adf66b7712c704eef6d69e48f0641d3bd20e7" },
                { "sco", "0a8057c2c85aa8bf84ed748365d9f470b20ed7581496d0b5e2f62662af475bb4fbc9ff75f4e3d6d5c66c32f612e3226fc237f5cbc6d9c9195291e32d917015b6" },
                { "si", "642a6cd4c05f99894dc03270c95273a827aa143e351e83f2dc2ca516851862833b1f1257ebe6c7d41f3324142ed3b5d9058f39b8e2fa71f2ef640c5a5c4ae925" },
                { "sk", "edc84496ecf5206dc253784b2461ef250ea4d7a7783e88bf71d1f34e909c5b04e5f43c779dbdcc15fc2e0aea7061dd429a3ea8ffd3c6b1e2cb5f2cbfe103211a" },
                { "skr", "0d64601277c11a5ce181e22464f4cb6917aa15a7526e60a1d94b116f887067e4506196e54a769c3fe17c1c81bae6c643d61ae414ec4c12a91b7a386c8cae97b4" },
                { "sl", "1d51dbc50801b0d0c9147fc70f34faed823143d7fe1aa1b5edb0d268c4a8e72e24d26e5c1a156e633e26f131fb97b62f7c1e42c8b24af814312e8f9bfdead7e1" },
                { "son", "ff1456e234db04eb86e383ea3db15bfc4c75a2ccc6a0c6ad75c65314b3148abc6e4fe4a95ae98e2a107761a35835f81105014df7a8c2e41efb0eed28212a0f24" },
                { "sq", "d6e859606f962ec6cf4764d2c43f8c6d2a2c900865a0fce1cbb5144b74df62b7b93551eb114040495718d681a01f6793160c2674817b4ea97473d5ab1bd6505b" },
                { "sr", "9854f7b350f5417079abcb2e9002edb78b6dfe102e8986f67e498e21a17934f1eb2322de3305dbc2220b1ff0aca8e927b6cde73553f6c83d1727b1a5271a2e65" },
                { "sv-SE", "9dab5967bbc7fe9cdfd123dd52673c586698fb927daa9c52b40e137d19f99023f135edc65411f831d5349a86d1ce072a4b0eec458b3f13231d120d2fe4f90534" },
                { "szl", "733db1c90537abf8480bef4a01274d350f34dc38b09d7ec16534b9d72a88afdde57e75295bf4f1b9701120a714aa2be141dd52c41f43715ae941d27617fd2b99" },
                { "ta", "2f1311622920840026ff588fbd231423fa3bbd0598578a5becb463b87c5a0ec40d724bae12667500259adfef2a3509654aad70e27b5a9678873d01f5a1d29e80" },
                { "te", "ca8ce021af7f89badd234668bcd7534f720991d45d3cf974edbef5706938e7dbc053029cfdf1ab3864e17fb234d6de65265891a39056a14443da0cb519ecac95" },
                { "tg", "e5e569d2018c26a450eb110c5ffe8ac896e5ee31db56e3ae0c2bcc16440bb66ed301fbf325b1ac60675985fc6b7329ebce35f97bdf4591a9bba20bcc1dc90d79" },
                { "th", "568b71a2d36407ae550d416036bbd7854d78d85a57d6834d734e015cd3a828e219d5b56528917566e0c10a4369ec083a8673ffff2d1a0f50a7e5fb37ee8767ec" },
                { "tl", "6ffa9b9f78aed1395c99451b5547868a7147017b81d67c902b37d7b30fc3b67e1c759859645c1fa539c38333200a69bdce4b58e97a17fede55f01c654015fe0a" },
                { "tr", "440224028d2aeda4047bf58eb9aa7c645d644662ee17fccbeddd58382ee874f7bbd18e2f2acd062f130c270db29a03e80b5f4aed7ce26a6ef6ea03346bed5526" },
                { "trs", "46fc78336ea95dac55c7908c2b2037055e6f619834db7debf3a0c6f29e959a22350496c53ff6ed20db706cc2ab8535581f85abec41ab14a08637edabb42f3b20" },
                { "uk", "2255693f4c02f5cfc91f9388d83916e98ba4570e96b7f5db3298dba1ebcd656afdceec207c11965c607bdde420021bf73dc77f2cd006f16d1030b8b59aa952b0" },
                { "ur", "92cae4b85274e7ef52035434e7e49205d39f80a817b020c887c5decf4cd87e80f4f538d07daf67a0e59503f88e9c23c0c0cb3ffb50e84595bf331d75172e2881" },
                { "uz", "da791bc0d0f3ec528cd193468fa33cc3914da62099620c3a194d6ff4e8ed7093b1a0ee9a525443761ab87a71bcabbe4c868a3920b4abcc768944e996d4509787" },
                { "vi", "f2747dcff7f3a06f23925b2bd2e9cae632de458e1901f97de21a52484b64ed7332fcdd7bb20b5a2e574061ce131b06b10ea483e7d26f3123de31b12ee45a4889" },
                { "xh", "723d2f65948f4c058daee3d0d5c026788b6dd125f033528f328885614db1877ac3181a5f130edcb282fe1f118b5a354ec11cddc70a3b86da5dcdfa2abeeeaa2d" },
                { "zh-CN", "a5c56e481ed6f73954710cdd0da2a03e89eceed6d49802e4463f0d4299d38b5ae8f8d08d21baef33eacbd6f5de5b2d109ea10e83302b064687bdd5830ff457d3" },
                { "zh-TW", "b127d48dea5e37419e539c6a3d1d97756868d4b0205018b94cd32519fba7ce15805e063aab42d5e3ad0af77ac95bc4059b752e561494645581c93bf1b32667be" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.4.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "26eceefda32cf812d9c2dba1b06c75c3c9dc9ba733883251af770f7d5a0a5adf4d3e9caf8c450b789232983f84a3f3c6e9dc2fe245e17152f73fb3e1743b4133" },
                { "af", "60168100081f231893851ae1909ee2ca247ba51cb533c8ede19c188f1b4ac9e52ca8093eaab9c193258c72d12bdce00ac380a6983c7bcdc73e92149061f8a07d" },
                { "an", "afb0197339b57cfc61655d3f4ed63a727edae3bf5190ef9b0dc0976cf8e780ea3f79fcdbb0599a7ab5fb5aa059a8bafec8c9c6489d76cb4b074c732719ad258b" },
                { "ar", "30d834a7f2dafaaf8eef94b6b5be4f1ef4c3e85bd3598b4c7d15ed42c369b313ed1adfcc66c35ea08e7473e3515d030d0070c80c1d817a0a9780444cfb969654" },
                { "ast", "ec963ebd2b1d4356206cf6c1f80bbfe26812a3e27b0e49bbb5bbe9509bf45285b1f4c203ff83b3562257418d8a2e0a787ca76f14fa5a425992073898ae223963" },
                { "az", "805fa44308553d9d7101d70b1cbda80f3762a6b83d9322271c9d5ec5d54ec5fd004f07e71fdd1db54bdcf9a9259d9c890f47cf6dc575cbfaa7e55b8f49181cc5" },
                { "be", "374348e70741932b66df1ad85be27de64eea3b00aeac275f6696fff6adb9feb18aafffec619b3fc0bf7e89640c4de36d76a94a0840b12d77dda0133b2c4bc9cd" },
                { "bg", "9626821cd6138d582fd72af4cbab69a9b8634201eb7f7185a3196fc1080815c058dee2d3e15e123537b0edaf0a246445dfc3d53af19353990e86027331be5acd" },
                { "bn", "1b40b6ecd7dca1c84a421e55126cb8065e1100f59ea52f6f94230dab01f1587dd421c3b291c14f707e0d20ebbd981e6087b147d326532b7f0381c2aab32f8bc6" },
                { "br", "b2ac3898019d861b80c100ea8a475a4b02094bd0df2da3629654b115a4066f39f82b7a7112872017bcc82f0a0af6f5897543ad43e8ad46af2ee35a54c730166a" },
                { "bs", "412de238a30ffcaddf559b8a523d1edda43064073d095a1a2d8c1b919f8149f986789d896f04aac55ce2795d68f8dd45eef31117002781edf7e9b91ff6cd3c4f" },
                { "ca", "8f94ae32c156371065ce6d211da88f5daa553e40fceaf17b862def17cef050e384d0b0a0dff05b927fa8357550bf2087b51c1582f378539f360e93926fba8a4d" },
                { "cak", "fc13f04a0d2d0e989a2b9a145e6afbef5db937cdf9470bf024901c08bc3aef57c9fd2d51aa374c6b866b1011234ab51a60c72be4c9d0b0905f23c6e2cfe2a49e" },
                { "cs", "d8048a2d685acbfb0b19791de72013bfe5c8ca6ae7e363d13c1f267da15b9ddfd73cff630dffb403ed82269939dbcec5244e26439be7114b03ee1a6813f39958" },
                { "cy", "2069771bee428cb7ed16b08960e7dd2209935cfc4c2c9e53e9fa7d8ef8aa10157e45c326f9e96be2bf181da69f41d9048f409ba2d0fa03b80df05f1c8e5e59f5" },
                { "da", "7ac313cabd86bcc28c54eb64425a16618191bc0d5d9a859da375767e4f6464b2bac1ef65f80abf4aa5d7b144f756525832e261a5b86e9ec095fe1cc0af6e6c3c" },
                { "de", "5222f8d51bdce67f7fd5ba40ffce20b528bc879e2390a2c17808653fec9b17c2756bfa3a65c6fbc8d326264e86106d5984d41b5ac6a2de43592fb3f9e2c41309" },
                { "dsb", "ade3f1ee05658c9132df73c7641140ce2d1d0f36fffda6ab6285c641667845138a8a09069efa782bcc58bf516ca1355009bdcc00837da47ab79880b6d2e1c894" },
                { "el", "2164ae2b2fb11b512ec6b7049cfc49001094abbf5193b17e05fd4658a0536a829074acc40a2d1edc00445322843ca2fc9601b9344184f707d7b1481fa4ff2087" },
                { "en-CA", "8e3c93260e43553ffb1e4503bbc1a76b28568b25be7a11a6a9af40a6236d53b9a232b5cf8e9260d667077ec22617966f74debb893de92e7f1ef3badcf86c156b" },
                { "en-GB", "fcc49d6fc07d2ec73e573982607ef3281e1c061206c9fe600daf778450515c0b7846c3876951995fa959ea8ed3128f804c43234d860788b0bd2bcc3c9037ffb1" },
                { "en-US", "d1a3db7e60d265ceda4610ef54d7fc5622e342c9b1842d54be130f88259a078b662387d63adc1f0497e94fcad826693aaacc980184d239d2dab9a23a1692687a" },
                { "eo", "890f94f1347e3df1211d32f1c397c4685c3e86280376b385d3ad147850de7c04f590bc303e0c82f6c8f2ec6ff353cd4af9d59a27a91072fd3528b31c3bbb3352" },
                { "es-AR", "e7f238734b2ea7adb9710fdc822558cbfff7814083ec71080ddcd1c3b848a6631b7c4982c6481e99f442f32547bd945fff524d33de51ceb95089b575b4c9de30" },
                { "es-CL", "2a6ca8a2c231aa058fff366686579393c26adf0500cb48fcbbea04b00941c3e48a040f008a2a481ba0df3f5b6a0f06bca1dca136e343bde483ca0df3b7b224b4" },
                { "es-ES", "e029477615caac723819b56c62ff1d3e647a5d9ece876f71b50578052fd03fcbd9282febc5de8a6fbc10404de58caea956c7aaf037e9df865f0473a0467d6cb9" },
                { "es-MX", "a4c0b17984f0315bec8bfa2b1743069f7299fd2d791e4ebb08abb35411e0b8afabfd0e19bf2da856dcd70d7eb323c59688070a3669be49ad57eaf135b67ceba8" },
                { "et", "072784708df22c54b5f62b9c1346a811a8791f1df2d0a3f82287840c6c12ce0f9b48f8a58fa4f7d9fe9340add1ae0d6d5dda60715a017c72fefd70ad2388c22d" },
                { "eu", "fbc78924de0372e72d43f9359c445e5fbaf514907d38f9fe3787dcacdfbcadab92e1c08ccd2aebea029fa74fd8d4630fc6d89699fb745c3c97b4a56395e79986" },
                { "fa", "3d5802e66f2de2217fc7dcea9f8fa4f7e5aca5475e74910dba8cdc00deeb4c646e7c857823577c012391665b3abf1bd7877ea56f3817da760353da0698ce5114" },
                { "ff", "031ab83e8f938e16a1af16b21759c83671c4aaa56f3e91b9e3575d78e51a99f3db0d0e7fe91bbaabb1ecf733dfc53a9707633fb9323aa6bcc9fd598eadfcc922" },
                { "fi", "610db1a95a757fdd877ce73f2a66951639d892602d21117ab69e68dfb80dfde81efddb4fa5c12e1d21b431a34b7c528dadb65393d3e6cfeedffe17fadb586d2d" },
                { "fr", "f707c42337f4b116930fd23dd3727482e3991321f96f9afb7429000d353e95c096b321790ffd929a7c99f5d212e308e035b723d5afb39f9f7ce654020492cd14" },
                { "fur", "fa5c6dc98892ac8e552c91729a9bb6ffb87ca9ee7ac7bf47369f107a94324c0f14586c762323ed49bc36cccf47dad1f60676446fea7fe0b291c4fb130e201ef3" },
                { "fy-NL", "1c22554265ef14cb0c5c4d5ee12e1d676d7a2994042b4e694a04d97a07bb1b4626160a8a4ef9b35d8dabd8d18aa9d30e117574c47b436fb9be895667eaf6da12" },
                { "ga-IE", "7c09ab2a671d31b3947f3e356c8d7cf04bbc504be9bdab70130806431431ee7e63f2036c3fa5832bea85a3c51da268695a6ef4b83d2f30ebbbf4c182892ab88e" },
                { "gd", "9ed7bb9b3f6ec0e07bbd4baf55756cafd4b08e836c3c0fc49bdb803c45750d1789d0092e6dea57033af8b3b373d8d6db1529429a3828f3c4413650ea9900c052" },
                { "gl", "7f402fa118dab80f800fcea764fcf50208a0efe3681ed1d78fdb527b611b1bbb7c18455b9e8dc9273decd8efa2d04962ba0b9e4d2661ae01df9c32b886cafc99" },
                { "gn", "2acfdc257d5306d1b933a36574bc3702127b8ba309ce264e7b98c944198dde10d3c9b4aa3796e853bfbabcf8a7c6db6646747ad3a975ab56a1059c3ad7d8b464" },
                { "gu-IN", "b5203773261e896343e05ffc92c59cde0c8ce0cb52118e71531a680b69bcb2d9766ad47ba0e4ffd1ab38099c6058922fcb4049147162e7fdba25ee6e1954f006" },
                { "he", "083fb3ac610632921ad5b78465a32520cd0f2adf4d25413067f8a9ca8118131cd3a426338c003d934497bcb7403d9a4e4b55595d925ef1a5e8af8b79b7c944fe" },
                { "hi-IN", "867a353cbc198ae17826cebe53bb61a9e50be61988737667d934dcded7b2bb9d935c509161b6748a3ff79db57383c83a8c31afee2e2c1fc3717d2591a4b3fd32" },
                { "hr", "73f19dfa463411b9ebb45665876c1653156decccb9e319b2e7a25108a4fe39d921e80b7516934a71aa41c80efb162fd76c10eea77310030ebacc0978e7673d46" },
                { "hsb", "c73be55d0c12a1f91b9c83e4978aedb819718dd3cb7bf548a56aa7399e2d0c485e2e31441f1d7a0950f218615409c5e1eb85c3dbd9cec86671736de83c67ad14" },
                { "hu", "549c1adaca681e3642e5572d5e2b399abaf73e09cb2e2bb3eab89cccdef2c2a3db1a7c0812b29cd9073f72007c21a389395a75e8c6908f3dd164698c991b2c73" },
                { "hy-AM", "4b4d4d5f092e8da803ae1f8e5d9967d6e02b667b00bdab222bc566b105559eb08a97450644873dbac3e08eff00cb4d8179bfefa0a4f5614257a1befd42d66296" },
                { "ia", "385e1bf3251c6d7d3010ea87c2062c22e6db4bbaa0d4205f719ce8d8ceddf009f1218f077b75bd4fed81bea010c5e667e6ed527a73f8163c49cc0172a9bd36bb" },
                { "id", "75f33b4f217a78cff079f085b0a3e68ead2fbcca25f86d0e2a632efaf88048e17d67319e62f31e283bad0d0012412745617e5f4eb3e1e6df0c29af2199e6273d" },
                { "is", "864fbc9a4588420a769f2759da9f92fc4fe8ab428491bb194d840c84fb8d835dedd99852bba5300240f77e232f343fea7ab6f288bc9bf29c09d6d30619a63617" },
                { "it", "8068e996127b13f484704823985d33f3813bf04f4237627b03257d2a4528b5aa453810ecd535c0923692cf1b13e93b800fa71c9066ffc799205eb825c74a65cd" },
                { "ja", "e1028249ce12f1f31713bb8710c7069f70ed78a4022e67c239f8e4dbd142b03b028a9853a1a9b98b5614fbfd49101be6fbc0ac483b3869614ddb4d6dca0d85fc" },
                { "ka", "239561ab8f4b8a365a7b645de735a8fa061d2e3406fb5b3c8cb486e84626527a0d5597963a2a4ec4c7fe332fd0c109835de5fc00bb8903a3adcb08d1ac4dc6be" },
                { "kab", "1b83c35ed2a9b4da313b18f795224fa0180d58e0a24eb9d93a5140040541726ef6540de9ebd3f1618c1747498569352043adec87d0ac4a31a75cf7a990de6ed6" },
                { "kk", "2c97378dd827fe2b31551d7321b2b5dad5a8e42885e8fe3ccd05b969c36da259e41cb278c84f10afeab503443894fdfec9731f62c790b45c30ae396e8bedbaad" },
                { "km", "c4e31f8ffbf821e24723b405d2afea671e4f2a78dd0082f4f2dca672fb85f633224bff4f825f9c23a4849087d4442eb25e3497c4831924ab48e7d56e185a50aa" },
                { "kn", "4c02528773fa38b05ee2d37386b6ac895faecfd76f6879b0a41f9ed272dc4178165091f0314e12e8e51c06dd1f29bb8167e3240e34ffcbd52132fcf09d0ec13d" },
                { "ko", "d42918e7b8ac9d9c935b9d16c8bf83daba98865f476bc9a8975e899bcefbf68a4984f4a9fd6969a08263207a16b837c86d1dca36534f1f2d83bb37e655a930fe" },
                { "lij", "8ea73d036bf55bb48c86a78cb2f7fff08ce29d48eef02f3d68b2ee16506a28fe66f70fa217e1d3eb2fce036350bd62ccbffafc26eb2b89fa2c18e002f882f611" },
                { "lt", "730bf52bdff5d970d258695f3b5688ce34ce2eda96f1380f689f4c887383d8ec02ae4a407852aa62f840bef0189b359be51f1ca424ed9682af20049644b81d51" },
                { "lv", "4b223fb1286a95705f7e55773fbb138943659e7cf4468344fda5f384c5bfc8dbfe63e1bfc0b3276560594994d5066517240971797a751d8f1a49dd198e68a794" },
                { "mk", "ca0957b7c570f513278486f937c82c98ef2b51ec906124063aee791814f3b0b34f42aede332f7dbb8c48ad3fc4970b8038dfce3344b2c9be3819fa0aeea31007" },
                { "mr", "18372a2ec147f6edff361fbeb17bab4024a0d5dfd67213012f289a4a06aa91d211fcffb3682009a4d0e640ab11696c140f0a76d45fa0a708fc7640482fa961f8" },
                { "ms", "f633c8c443152f2b80a2377b512bb8e7037f602efa5e553e8b1f147febbd54dd5c82c503d6de5c8ef7eb27423b12fe8e6665eeee6a1ed8545dd81788be2948a2" },
                { "my", "1d78bf5b5292ac7d524ed7ac0334e7a924426a65e230a4af7b1c4a111bc0bfe85d263da2b7ad9b7c843a550bf0e3337d394deea87826f03edf8c6cc873758461" },
                { "nb-NO", "6b4dd7a5933753e61f8be834adb536000532c4773d2e0379e27dbb186b6ffaa86c24f5bc0c933e9c9d07ea61ff966528ebab63b3dacd856f5cf17dcfdbb4fc29" },
                { "ne-NP", "4d53c47a289f5a81d734f9c460a659a7e7484c00627be23c8522ac5270d396402532c19375b988caf854f5394af5de91f2e15507af9f17348e736787ce254925" },
                { "nl", "2963c96be0052704fdf0b34c2be626e7275b4ea422d2e1c75e7d8c413cba3ad1b211707dcfe1804bfbddefbacc7e41d016c8631999eb03e50e792e25c170258a" },
                { "nn-NO", "9768200393b43d183659d06c18506cb1ac48d8d51866fea954ab09ba735d6389276164c8952b42eb4eef1bb5c6e2ea2c76cac95b4ef7a8890731588374e1b809" },
                { "oc", "ddc3c7b624cc221267e477b99704de6f65cd9c946d5c4a9a6d4dfe76a023059b3d2a94ae62008dc2c95b2d01cd317be16f5ae645f3955cd5efe5e2716ef84faa" },
                { "pa-IN", "7d1fa1b362ed73ff1d3fdb0cd00ba76a889b24a62b0894667238c830649bc518b7d4abb74d7f3b7741a3730a92b7b572b732268c102d802b528bff5a11f40f27" },
                { "pl", "1b911ec00adaf9b42119be9e1c3185e804e7e486497f3716c5e4e297c350111ec960ab7214a65f45d0a0544591e395e4d26e2ea49c813802efd2cf8768b17fe7" },
                { "pt-BR", "4c5a4bb11bd6536426ccff6a9516caf67fce5426fed268d039d97b374cc9efee3faf6e1807ae655a7b703b592fc55f6dbd1dfda6dc62a6bca04460460bdfd7a0" },
                { "pt-PT", "a8270719545cf6474f81d154a84de888d26129c0084c3b34914e046cfb1f180a2a83a8967a6b84e5e0940bddf7a934455a47e06589688dc3df97a107c96817c7" },
                { "rm", "15f1e90d13e1a406d59b0a5a46f46ee2ecfea84880950b18e3a23b79481adb9a594a390bf739b9dee745ee2275d30a29a85d9b3285f784c57a5bbb1c823190d7" },
                { "ro", "19fa67e8e2068765c6f410e45f6dba983fa4c05aa60e6d30b2ca33c32d37f16edfa23f71e1306e36a75f0951a3ac5b65e75dec13f18f05710364c4de04307fe6" },
                { "ru", "562b02aff22bb578eae2633f0df364e40112a1ac17a04da2cf80d477520d6dd811dca5a70ba2fd8475be60241dbed217a810e79e56ed64467b33a11d0aaf8105" },
                { "sat", "2c847210fea42f34b3825c2967446d77b02298ae1a4af2d5a3d4fb84dbf69980b7ae076407dd0354204b21b8a5d8a441706a16ba8e66cb2c97998dd5e1f720ce" },
                { "sc", "ec0351be8a2a722ecdee3262df88e97266446e2c8590c9e48dd7f2b748c8278ff2ed14cd06a5dfe8ec91c34e09508cfe59dc776e3fc021641322b182d42b690b" },
                { "sco", "7502901d18cf7df58a3d430e9e895619b57356b75d21232ef41e8496a4b4494474f84e876c1b4050043759d3273be4e1fdc214880febc5c5bade4ccc202a600f" },
                { "si", "1d2684a4a9dbc36343caff6a55f5cf2357d360f42c9ecaa2533e6953b35b8dae3d7948d752921c7bd23f188c13da6cc626a4927f1540baf110b84915b30971d1" },
                { "sk", "9e83b6c398dcd6f5526da87fcdde6e67a0340f220651a0cf031c645dcd4f3fa3c7cce08d99d6b51605373e0b4b749d176837aa313c04ae5bfefbc34bd9beea16" },
                { "skr", "14b2f69ad9ea666c924226aad7cd025f047729a76364dc7dfc20e937afa3154b205bbfe82ac92e011bf1b3c1d24d57aa164d35d29c907460f3d9a1e0aaaeaae2" },
                { "sl", "94d3580758f3ffce599b6935938072ef6a9c222d371887c7deeacd8f4c2d7caa0f5b94a75abff6867b5c255dc14db584a9cea3e56b53d20d7a57fb33d097f3e2" },
                { "son", "e1e6c36bd520b28e8f1519fd6dfc559611e0bceeb74e60e37cfb9b5020efc89eadfbd3d09de122d196784d9139f5a10916f308da86bb8cff8edf989f124ebcc4" },
                { "sq", "05c13356a920558b7aed58f2945367737a1f912887d715e6b0e8d67e5b70c182223e3c9019f73cea6cef76596455238613ad393edfc4555875e7720ece7fe727" },
                { "sr", "73c8901d19de120b59ac76508ae79a147ea7ad4e78e13c624095753c82e4374cd4509f3c4efb5052e3ec0d03ae9a04e915971197a74248684b16e2b367d3a7d0" },
                { "sv-SE", "30e7c891f30eb9f660cff7b79d7da07bb563c0cf5543e737b7ee82be647c73a60b8c18c55fe5f0e55e945307bbbd30ef52968f129ca5684fe039552069ee0b3e" },
                { "szl", "595bd7fe2fb0a6019d2288a38ba4135d6230d58782126350a211fea95dbf22184122e22e2c62518a0182c58844addbe1b041df65398a19c64b15fe636c6d9d5a" },
                { "ta", "3fd3667743551f35b349caa20131b66aa572068c27d59e46b9922ddb9e2e6404398c940c4a1957cee46bc72c30f6965a150d36c1c4e095ec2869ea3aa3346101" },
                { "te", "4c42ef821e40565f6d030d6549d21b306b31803737c3752c2dd40ba904e723271787a778e11b50e772a611e3091204a757aca8d3d41a2afa14f07031b9686002" },
                { "tg", "e4abaafd4f9068f48bfedac86c6ce3c7150c19060dfa5dcc8023d1857b2186cf2515c7eb8f861beccdb797ac77af61efcc5b739ebfa7aa987da8c882b0b22a5c" },
                { "th", "be82d22d9b1a38e9412a735b332285eb100612661442c18339d58d940eb98546896c8acf37399ac357ab8f2e83697ee2ee5fe49e56a2a88c306d5b8c3d543a27" },
                { "tl", "3be76bb99f630f246bc3a1a861d2618c21752f6699bddca71e5569fe2bc46e129aaf7004437e6c3758d42951a7bcd5699981c1abca695b3794326ec0cbd90893" },
                { "tr", "a5d08fab22e2df38bfbd9ad2f15010f08bbe11f540344cffaeadc3d9d0476daf548f9a80039ff08549d2026d5c24a0143f1b433f19547a458c0b73345d98933b" },
                { "trs", "0e5477ce0254df1f25becc19a46f53e5cbc326936933f6861e24ebc45136e61ee2b4e7a6e7324526860bb5cdeb9580567b51e006683bde6f931729221cca1fb2" },
                { "uk", "0e6e2d52bd9394273466b5f5a0a48a1a003706d63f5e074933af40e6aa3ae569d00b924676e3af958d70799480f9a44b55ac7087e42440716586f8c7782e8c6c" },
                { "ur", "b5fedf7fa4079c584c0f08065517e437567d9f6af47472ef5db4fa7985a51554117e7ad87722b4e1c785ff11ae1d10c18439d02d819a25ac1a3380a30d3cea03" },
                { "uz", "6562a3f7ef598108d4243b44c27337325a98a009191c3f9d7f92944d364615e8425815974132338effae758bd14ae2bc4f32a7349a2ab5ddebf578fdf8b376f5" },
                { "vi", "4388055d4452e492c38c5b1530449a4ecdf6d9a6af15537ee4993af6b77e859b21ffd2619c0c300e70ec7a2612b04ef3f1f616b05c7647169fbba44f2c0e5fa2" },
                { "xh", "1473d9103d12a81cf99b6f2da990abe11cc13c1dcabc226264561427ea49b46cb58800e68324bc201f39605bd2b76d646589b30550c35272550a4058f9f1344a" },
                { "zh-CN", "704a75822ca87a5c77486ffb715a4b0f03bb0ecf5105a02b72ce70559bc566a2b028b9cf3ae19c8d91e4a9b21efde5cc5eb1c9e68f7562fb26ba979324ead01a" },
                { "zh-TW", "32cd4d6e6d7de464202add1491e2177aa76ab0d3471d1695b7a7fb32e6e21501267101c45855adf97b5065d307f575326e60141a6bced01941e6df7080a9a5e2" }
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
