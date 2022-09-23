/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022  Dirk Stolle

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
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
            // https://ftp.mozilla.org/pub/firefox/releases/105.0.1/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "3897a5012bcf7e2e6f50a6c5033c5341da2b7c5c53131230e4325d3101b912962445d30030376b53753a6f47a8b4c6c8c5e0f82beeee31807b592f37b61315c0" },
                { "af", "ed9f4bc0ae085209c6c5196c4dd54ded6d03542dac6bce890a79994b8efa262b6b736e983c43b2760d750610e44974a86bb020d94f165b8e2df8a5b7dfc58e69" },
                { "an", "cfc9b73a7c01491a167d2da010ea354d5ce0f273a0e31e4c2f717b6b648a4189d4483e8877ef7dde5d9b23c171711b70b1c1c8b503b78b0804cd92087c835d48" },
                { "ar", "979707032f51127fb23667fd605c6c405ab5ee8910b28b1feed3d74afe8ef1109b4e15a3c3f209f7d4e622389d486d426211566ea9cf5db150cff21d84ef6258" },
                { "ast", "36225629ad0bbaf92e6c069b9650666b218e7c4bede3105c26cc7efcdac3e45ce9268d877f937a98c99bbc7493cf4c6930b527e056ae67be134fa233a162b6d5" },
                { "az", "5d582159333161bc1cfefc3764e04e9e9981c2073a91337d96728e54223ecc70f579e18625c3140e3314f73ab0d0c1d7fd6ceef3cb7bb6c0ac2ec55c3a76faa1" },
                { "be", "92dc99a4aeb0cb78147f86c88a69f58f748d2477048b156c1de9676aa61b6e125f2ecc187b15c93cc1e68af01b7779dfbc86c29d7a55432c42ea31f3015f9bcb" },
                { "bg", "796185d9ca079cdfe53ceca74f29b109302adc6ddfcea9615f005dd9169eb42a63a0d2f446faee1fe08c5fe84a2bbadaabeca7a4e8c9716b55544b76255992ff" },
                { "bn", "fee3db502c6ab0e0590da09641ce94183291cc5c2598f34af03e58c28b9365f6d0adbfa7a8ddb454d784cf3473777339043d74969c7c8832312d31d8e62fb8bb" },
                { "br", "e87ecc43a66f33847b789692ee52e25184f8585afcacc37df75401c99cc6633ab4ac801f8449bd31f3b993a80618088d085a82841d06712ae1aec570d40b657e" },
                { "bs", "b215a7cc902bd377b4a292aa56169149337aad80b10722501b51f2e670393d01533e84f247a672c68fa6d9949f87c62cec636bf07aaeb5e29afe47d08857ceaa" },
                { "ca", "b1d717bcb89ed93986f8be2b41887a34202095d133e039022f98e70b039721b3b41bf0394812caac64af41c755d91f8a1d1a860434b0f65b02e9966093c3f449" },
                { "cak", "98680db23933bf31401b035fa3b5e756f99fc3745ca0f49414936cde281bad4908d15425f356addeb507822264a21393c96e5e651f8eff36e9641fb7954e3d82" },
                { "cs", "9f0a1721de8a0277fbe7f762c7bc48f23821cdab01aefb924e6273d46dce6ef4b88f5fdac481d9c7c62b87a707462c591b1687b9e22e038cb51464c3f3fda1c4" },
                { "cy", "dcbcf5c43a44a14c00fa1b93e3643e14feaa2ca09613db2e31b455c05137bf3418af8255c10ef338e91e07cb577e4e3737718598cf386ad65e2936bc5090ae98" },
                { "da", "c65492db0b1ba93546eb8d400a542daa44a43ee53ac76fb624c77df37d856b508a27c2656764130265ad760b9a5ad231958824cef9a53e5d88d3abb5fd7ec6b9" },
                { "de", "51b6518fd65b3d3cb7239c0d6e3796679c6bb65b9b517abe0f8635ef33471aca9cf171ed8a2ec1177c0fa80af46c0a7ea94aeee5aa3d9c543eee6c70422e2b65" },
                { "dsb", "ea8371c3940f14afd4e20aa23f0e743cdc8fb5c212dd7346bc363e7e858299357d7010140d6dda4eff7c62a5f62c325b86e488ded84778bdf3fdf3535f16a84e" },
                { "el", "bd9b4bf27d2cd0214d101233ecec98bf073aaa21bd67fb0f520a77dd84825d0d6f7a80951c8d0a52711477ba736caf6495eb2dc8426884a7c29ecd586a712de0" },
                { "en-CA", "03e2f3c4c13abcbc1069bb7619f44e0857aaab9c7fab00ae5ece01238ddd493db6ac448edfa0823b9825b4780c4d90f8e1e333ff18d68bfa257a6c61a5499874" },
                { "en-GB", "d6c2f6fe3ee920be57b3cadc15f76ec3e2483714f68a990c337dc551c303a0a3f2086e8ba0868906ebf88c31da4190611aa71cd70aa4b1480a7bf72d92018a28" },
                { "en-US", "fd0157eecff8d8aff99bd65eb728808e767f9a1303899c56fc26feb2606f7b7ee54662bcd3a4e27f84d475fb6c5c075990051106786ae1a1adeeeadb857afc8b" },
                { "eo", "0281599d6ed3b9e9cbfbad9adeaaf441dd2c7bed9212d6fa8cf57e83f0856c26472a8a76e034d126e0ecf8f0eeeeef99ef27e8e0f805e2f8c36d19d590a7b32a" },
                { "es-AR", "3b12baab019a8d4b2c8ad48c9b16027ca763a65ec98b73482e97238db20995d643daba011078dd08c8aedec57228c6a292689a3054d0beae8e9374baaf7f819d" },
                { "es-CL", "f472966fc8764f55e8ed78b26d82d863135bb2981a7aee4fec2e6a8008dfa0deb0f3a12cfc84bec473a7ee8940522ee174477687a84200e607aca23f53fe855f" },
                { "es-ES", "f50fa05205bc17a7380acd280d0d2e86bef8d0eb6bf2d8411764ea99e6c093f7edbbe0d2f425652e2d74b22adb129ae0c8dd08ec135f0277ccd9c51cc947b97a" },
                { "es-MX", "6b3a6f91eff9357865f15cb0526df8580952a90490d98ba9642974c73b738f97493e793443794215c9201b8a44d3e4751ca10485918e8fa43dacf39afaab6a9b" },
                { "et", "07a8529e60cd69efb3623cc0192a8c88a2d9bdd38d8fbbb5a5d6981a50ae3e732016fe035d0b2dd8afbc2cf2454471951ac14e908ea03a0d0d3581c7629a91dc" },
                { "eu", "b6ee0a1b9ab534cec67ddec3e47927b906f9dad3ec69be7b58886b2ad94b1acc5cba27fc3687a7a5ea3557e670906fd698a60699f91e9daaca533e033884644f" },
                { "fa", "f7c7cbbed96786163e9ededb57a745774efd33d797a3bca735d6cdc6a05902c11bb69a696ff7778bffc967033269af8deda33ddf5fd9c3a62f6d5ba77ecd4747" },
                { "ff", "1acd3b1e681b118ac5660d20fc7acaa8970c0e394c442b09a7494c5d7c0246901e7555906057c959b8e28e30c9cb30c10b394278f5c338f3fcefa59e8f96ad93" },
                { "fi", "4ed0398a2e0440e3ae8e79d5615b8ef318599e80b0272b532c07f8039bb59b7fab22c0c68ab234377c781fa164607ea593eebd21914a69c20ef55e3985aa67cd" },
                { "fr", "7d96ba6fc86f3529bcec0ba2e2bba3fd6da9ddc3b4ed3d8ff8d575fa7e450ba7baf74ebe65e626937b0c2fb059eea0f5b577b92aafe8a57e5cad0103ec87cb86" },
                { "fy-NL", "1bf380c153c57c084e46ab4c3b163ee5d1c1e96a02d1aa5e23a15b6faaf31e2e73da5eaffc37616d5efa62bbb222fcc7a316b87d0f319fa8df9e50cd93229629" },
                { "ga-IE", "a77b8e72c54cbbc4794143f2420b73e8f211375c4e6a23fbc027dfc0e73b7a72e111782799caed79c3e0892ceba6184c510801c46f92b488f37a860286ff9bf0" },
                { "gd", "e7ef7f326b1c5054dd448821ca9463a073120c5bc35ca08338a835cca8862eb67ee9efd649ca55234de47d83b9bc43dc2bcd35d45a6cf608856784c52770c8df" },
                { "gl", "3f6e0039357643003acae6ccb63f9e04d9c4627e9bb7621efdff72508741554679c95d9088fdbfa7ebba8eceb7db59228f2d5a35613a316c7475172d45ab9af0" },
                { "gn", "4bc2fa0ffc4f2e59b39ad59586b91b433abe55ae29f3bb08868622420a370429715b7c03d3d46040f903ecc973813ae0b33020d027f47ae602609f2ad3ae4e78" },
                { "gu-IN", "d1d19a2d1897dd31321fe12a6e255fe10b45da47fb330d901475521346c7558e0323748fc341175ec374fda44d0e11c336c74167adf4fed7672ea6ca5cdcf342" },
                { "he", "db9e919c75fcc6a298720136438fbe73da9c556bcf855e513d197f2cdf9199ef16f9ede91eb5967d9875457e6af4c59a730126d925f9ed65f3fcaa3366956064" },
                { "hi-IN", "5d2386de58c91d91dfb30f63fdc383c5c4362ae058f1004704f030d7ef422b8a3984e189491238c99afc8153f792830e555ede9013b4fc52923e410da31b943c" },
                { "hr", "eda05fcced60c3a5a785ac992d3dc7327d653a4705ce7e9c827bcc814a2609e0781b31cde2a1f6f13e2fbd7eb01b5e23fadf5f8e9e87ee4ceb1c700b7411cdf6" },
                { "hsb", "75919aa1ea5dae41a6f284f9a3711e00a1e9f28db5566683052ab281ce67b70dd531c5545d06529d07cbda5ce407cdeec8bead0e4f67033eee023ebcb41d8d0b" },
                { "hu", "9fc336880792e3c8e694bd904e88d0d6050fc1c9496e8c2d2f21f1684267563ca2c701590d768d3285b487b2397ded3f9c0e78fdffb30d0c3429102fe5276135" },
                { "hy-AM", "0c2a69ed84da387876255517ca01d64622cd4f5080d70ca8603f5e9b8e7b840adef93559493c9b53ef21608e59d7161bf8b06ee3ad6b6a2a1e7bdb93ae00fd1d" },
                { "ia", "a5759c25822d01d2be48765700144be05bceb2d1cdc57d43665467cf229881724e6e05f631237635a12fd01b3bd41ecf35c8ed9788a6be4d780702f863496ccb" },
                { "id", "23c79fa9dc79d2d95ce6a723a2fcc95fcda8effa3dbf9506f9fdaec028a0a98ce270003fa2b403afd9969945c437f75b5308d015aba85fd4f5f63425165d6e4b" },
                { "is", "d2417f9905968a5c7e252395496cf761555fd2ba501a2b56bb5d409952bcd1df07f66f34125bf00b18530454ebe6d5ba4ddba62837f4389eadf5a85ca25d9658" },
                { "it", "5ac47a8f1eebadabcea6bad392ba7064316c1eb72d657f052e136e3cc2d561f6ef4d049a96370fdcc4d03afff1ea8ed16d3fe64d8b9ce0c623c845c93ed8bd28" },
                { "ja", "5220887a9be5a536a01d8f60ffd84fb1685f6eb4b8bca94cfc7a8b843e319bc81bc41f26255d816c36b31eefa0353d6b163863ca324346c05a28555117a067e3" },
                { "ka", "4243b399f0b104e372d056271546c30454da671c5d9da23719f730952df5ad5674de58bcf0bf04d2be0cb5fefb56a3cfd86fd1ed655658fc47fda26970942b4b" },
                { "kab", "d2074f48ecaff31c68cf4d7ef90167a039fde73493ea93d9fe044478c5595e4039afec12097953ec7df1eea9ab152b3f784e6c9aac474c5b14d8d465bf215044" },
                { "kk", "8ddcaa9182cbd6832e52504d4046704193d88c51f037f2f56db7d9834d953633665645493d7d99fb413a7ee9e9c96257d097d1ff5d2a9aa3f147193ad2ade65b" },
                { "km", "847e3ccf1531317f8fec781db33cf8d7fc3956530b6f97fb6c6ac681d70022e3e9f4a405ab3bcfd2071cd0a24eb6f0d72ffceb50d770f8fa080887c0f4780c09" },
                { "kn", "83d85f580a40cb51031b2317f8078200c229cc7e8b3f13dd0acf9fa9d1a5f634ab838220098c45e1d8744df064dc64e72e588b8897342583a7ae5a58392ffd2b" },
                { "ko", "195cba6d9d387019614b223f2ccdfa5f25eb43223e5e2663fc5b2c8566de839c501b9a126a218952896969d9769c67a45affa03682f283050ab511fcb40b7ba0" },
                { "lij", "4bb9c2b078c51a50a92a289304c7d487d70c1fdb00cc0bf63ededf5c0724d5b0ae1079348a53ade59df9b0def43d2690d97479ac9b2981aa409e0783627be03b" },
                { "lt", "b071944b2bfd30eb9b81f6b147753e37587910b25f29eda23d73889e4a909026904b09720ad77219c5c6bda3424535b37c1c88cdedcbb9fce235e8e33c46c00d" },
                { "lv", "6935fc1106751b81b8a961ae215b7d240f7e2dc2677f988e118e4f27926c57e3af14120a441017180dd6d675bb37ded4aca585cd821d1e34095ae5eda1b65326" },
                { "mk", "1d7b0eb58c90e2e5fb19889ec804ca068cc76f8ce20e6eb8ed2e1831ebe095af93002a386bd7506c1c2414bd4ae4b0a4f19912714fe82ea80ca3faab166217d6" },
                { "mr", "590a0a43fe43fb1b9afab0f2e6063be82242c9ecf4aff44a1fce969aa011b5f318072760777efd53364ea0732fab84d8b0985e1c5cecb5a416df130cf4263398" },
                { "ms", "a64590b893be8333e73dc1507b84bb1907ac762d07cbd83ccd0cc4059fafcd697f921a524cf5f1132035ed387359ecdcb585767a636759678da3e977f67adbf8" },
                { "my", "41b10f6112e2cb1ea24ff735c2f98eed6d516c6bd502bd1ed112e5093f25d2d1f4a4e2aad277100d2060c76fb52cbc5d2613746c9c21e4993a83380b541e4fee" },
                { "nb-NO", "00cd62025785cf791dd368f250a2f505c9e20ba9f11b0351bc251f6031b124acbcf7acafee1e5afa8538f5c7d0183c2f5c234ed0e3a645c24e0e2175e935f462" },
                { "ne-NP", "902ed6a9754f5cb15daad7420d97b4651a45b5b2cee65f9c2d563ab4156ac288b63b2fa4c49cb1363900328184cd07de079804899f7798114afaff5699068b2a" },
                { "nl", "1b99cf9a91bf6a9f997cbdacf51ab8b7db13198d4311db13b234bb341fdfd0bad0d4bb3cb205be589e57ab47d716e36fcaa49f43acce34e0bddc0fd8444fdf31" },
                { "nn-NO", "2ed6092d7db56f4df2ea35935a94cc30a57772bab0765c606d04d6407e1212e3ffc01ff115a067ebd69f684b79376b5f810ad6786036c3cee5c0f084f6ba0de4" },
                { "oc", "5f8c71697520b02f587297aa521d186c14a088eb935e9e757f44db4bc9ba9207def2394950b52ee79c9132b1bf0df4a3d3a8f30bee42ced87dae5db750a7caa4" },
                { "pa-IN", "96b3f9a422ba76454ea17c2009540f4fcb3d2288077323860f6293f90bfca1f331734901be8c12283fa7258b6a0450f315fd5b42369120cb94d9476f132fd671" },
                { "pl", "4d08acf7a84799b5462ccb77e8fdcbfbebd16b471c3d02f080281556e1245532626d432383672e990c38d4220497e2a618adeb182c5f5d0bf2f252da2315af6d" },
                { "pt-BR", "a4c2f634f7530d823c4e638e2f3081f1355c6cd03f8c35c044479974ba868e01bcc4c56246ba1e4e25fc7f9de30930b5e5173dd441e6bed50741c70f35d4becb" },
                { "pt-PT", "b3ef50a2eb969d12f6abaf416fdf09f65d9fc809b50210b8c9dcf2c7be18f409628971cc45d7f5186958514d8b25ee26604818464ff5cf7b34cb5038a52f3186" },
                { "rm", "8239c37fc68aac6be20a1907be12080279a62b13a4f84c200af22b149cc5edca1e4f87a16dddb0ae3c753aaefce7a6e13733e808f45a4dbc32dc4ad651ed26b8" },
                { "ro", "b9b26f1a3924fc1a66c6fbec3331b5a60dbf4bfa72850d8d0db69585ce2c9dc69412c3429a3a03fba52f7d6c64d0f428157eecd50f394fa5383daf561d2dc433" },
                { "ru", "64ab19c09b4fbec79e6fe17e544174692dea38c5b387245f7712f982f788db393c67f880e8c38fd651f76f103d7244b91ca95889e100e3931db010f0de9d68cd" },
                { "sco", "c5ee49403b563f4b13b80135c2bbd25d4d44f7637cadaa15b6998afa7ee5f3c38b1df9d6c931d6e12dd72c211f8349eb4b04b800783df02f569619adc9ea17d5" },
                { "si", "9c0798379a331493d8cded861c24b92212b591e42accd3ae1deda6420b3830a5fd26c4236a2d9817a7df4a96df171b732640cdd4300736c397ba7dfdaf61f49d" },
                { "sk", "539ab51f29c09a09d1e0d23f4575751036378c1fce7a18f1ead5c41fff1127e7fc7173e1459975af571f8538b278cafafabc3fa8908ce70b09423dd4ff3d46dc" },
                { "sl", "6028ecfaf5ca80006106184c1c20057a6f64a8f6ba78cbdd5aada57cf239598c8f541bbddf554a8bbe678f2caf51f229884f96661c0a8ab8a9e964b3a6ed3d13" },
                { "son", "4b5a4790a6611408f1210adaa9e10925139b5eabb015256f54fb8aade07566c1104259e04fb4c1efeb34254feed70dd3a2cb7e58b9a4fb8c88c8425cd475e1f8" },
                { "sq", "b5ff7496f71d57e4976e8be2c7362846cb32cb389972efad1242c48a56353bf44213ab66469efd2ab43c2815524d19bbaae221d416c252a360a1b247a4f07a16" },
                { "sr", "ae342996cbb355e5abf65169072e9750acdbc436c60dd51d2314e5b810e980b9a0151d20eb3ed01b5cd35022637b58f713b5672c9b78aacd6b5b1dbf0011bfc3" },
                { "sv-SE", "b9bf5b68023fc2c5762de14c09062eb0a8c5cb023904ee3ba6bddb1bcd6e8e2aff1020bc4b652116ab56c1e201199da2027942fd9874b97cb83118b0e8ec325c" },
                { "szl", "55516ff2d52439d6701bbf39063d76a4d781a361a7f817b2bf1dc3e2c0486e02c271190b47b8e871a7fe52a65206734ad41905e25b992d36fe83bfe201a4a78c" },
                { "ta", "e73f0617ac1c428314af71ae27a193d2bc0b10d6427a1033ef2c6be7cc3f3b0f403a3f48bf49f181a50a5e90bf379816e270bd36e17d7bb933139eb46688dc0f" },
                { "te", "84715990a1ec67b06623d72adbf8bfdd000ae8215299e5749d07cb69160b3b08bf60a82ce2834e82dae409d8a68ed17d637418d513e7f4085e3c5555b3ca724e" },
                { "th", "cd8784dc24a489c64858c25dfa4b6a6bff724f726c160eab47d4d71568b9ac8cc2198deabbdd7e584ae8f0340629507f418a8fb28926f5a6515e59e2b7d50277" },
                { "tl", "954178dc385fccd0ff11706af374b6af6ae18ed8da023a9b57cc9bbd1b5e463f3fa02f72953613d8f012edf29bde3685db965c2d282694db9c2c52554327237a" },
                { "tr", "99ea903e5354268b080e30b6eb3a7ab5656572c24f6740660060a56b2ed8da6bf0d4ed666c803286dcd9fa4cd0ee37b94077c954250153c305eb9156402e4fa5" },
                { "trs", "f4e5bbff2f91e94dfbffec83c3615608165b98eeb3098ea43e77fab2592795c13e49e111769e32ce6784a4ae9b4c9b4cf09facf448546960311160234e56c38e" },
                { "uk", "db4556940f47f53062e411b33d89da38c7942e3b89e6845e5d6af2ac3d071426a8c8af3f89ee327d1c7ed72d1207973a655db195f568716ff50ab3ae7b0333c7" },
                { "ur", "02590fb6fb22891a30d0a82c86d8ab081ff1115c7336c73cd8d26123f99867e0490d7a570fb0896f91122dbe22cc0c6c3f45be9c5af36edcb1d58014b3963459" },
                { "uz", "38491da137844b2707a0a64d9802a07fdcc30a09122dfc3b450a8f37438f815d7e743a79547b901031a986b4537b937e67363ba55e791460d3affd60a71db787" },
                { "vi", "6bc04285c1427938cd0d55e24c178f6c3f98b1f8395c1357404fbfb7f41de0a67d4749fa860300def1c2500df5eb8d8b8457102e1d3e766683c1464046072985" },
                { "xh", "6227f252644e42a4ed5f773815118cc388f5febc3691edae01ff5154a059b54c542c06093426b6f406b59eb71dfef0c1ed722faaade80bd4fd29cf0707e32e60" },
                { "zh-CN", "3bfa716830b9db6140ecfc3605b3e6982af4cb156d49aa41170fd1bc8f41d0036b9dd2959811cb14421f8f879ecf8edbd4b057f9ce5b53791d20e3f06c58a63a" },
                { "zh-TW", "414f4915b9aca91c3974f333627b2f248c0bc24bbd9a6a5c5d8da4887a9387c9ec3ceaa3eacec1273ce28b7680ef532315bf34819fee41e85d459be018c32061" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/105.0.1/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "1d189c16d0cb271a27f84b7e5a8a4b06ca4d2bcbf2f9f1de268eb411995f395e35c4cc97d336c4cf7a1eea746baa079b938bc55e85b0fdf89e8d7c7d98e76f4b" },
                { "af", "154b317f1ae4d5a48c66c03e3a6ad88a1720b05656d3403043d7a3cb45615b665a31576e4ddf0699b5c957ce5baee93ec6666a00de5dffc4e2aab6be519030c9" },
                { "an", "5e8ffae73ef1aaf11812fc3ece166f328503f83f5c5eef86d65e1d8fc72ef0c5684c3f52e4f66a74826b9ec8eb5e91c7209502341000c029237adb953d20dbb6" },
                { "ar", "4caa2d0ba9d0b0dcc514ca0edf38d8d98b15d9b3b53e29c7cd8e34b2e2dc29372841d6349fdcb98ca6d4c156f915225d2b309cd3f691ff053522e7a47be79c65" },
                { "ast", "9efbd9229d57e5ea40808fb5ca06bc9d943acc3e27959b6527008a8afbe0782f5266d4261ded80adc7087e15a57fb06eb0a1f619ca285b718852ed21ba796d45" },
                { "az", "ca80298ff82d1869e26ef11ff53a339cf6277900a13fc6f828743cfbb206dbe2afaa1a1fc6730b4dfd3de6674c859b2d8b987f7ffdea50980a32109080323941" },
                { "be", "df1151b5cd4ccbb94e57e4933a9a9121d3e1f614c395521e33357a45fa7bf701ef338f62db7890792dcbb8876bc67370770f061bf60fab9ebe32b6f910c2e166" },
                { "bg", "277e217e35d77d38994c8d21859ad8577c73314da8922d4bb91f5ee9a8f7aa54259ec6a23ae3dfed692bfa7fa886565137c5da60870a527fcb1f9dc1c84d49f5" },
                { "bn", "fbf94ba3cbcdf27eeb8e22655b2b0782112584106032db05549b9d51c54e46ac79712ddf082021772fae25b9818f3d62cf7a80eba4bb7fe230aec6e6a72238b0" },
                { "br", "7ae39dd6107fbfc069312ca91d2422331ec8abf4a9bed2df4b5fd3144432f12160bd64856923bd4c31952e9b8450158d94c851d96b71e055cfb39f6378988510" },
                { "bs", "03e4bba6033674fab467843f500af8baa1a827dfca050b78a4e941c2e529209a1f587adcd2eb95e6281c49d2db9a96c2890c114681159cb11890df68379d6188" },
                { "ca", "a4792aa204f175598615af58ff36223385220540292068b4c04eaa992d1aa70849b469882360d37b0f13608640c38ffceff6ea71c4a6fa49e156a6d9270c127c" },
                { "cak", "bc64b41b0fa88ead84d17202b9f593421e9d94940af01017eda7888ad3a546ae4d240206fb296390f912e35ca5e43a710b8a74f4d66156efedb09ddee14955f1" },
                { "cs", "a6511fbbbb31e2f99937a0dad04db63756e758a2b6dd96bb5b11323ec5c4ba6f58bc7bf8451afde2b4da0548b03f77df4220cec6486e27166910066f1528b19e" },
                { "cy", "e98a6b7df7cf320c43056868005e5ec918423916a457097665b18b5e89014d6b54bb6b1ee1c500bfdc2c5c9cb6d1c9aa5efb929225cc017c273fd519deb5b324" },
                { "da", "e00d9d07c9459c09129bff5703e9f060b510f470fdd71dd1b11654f5735945a056bdba8c674056553565d73323d6aee6e5013cac34065fe897aad55f60a248c8" },
                { "de", "8f83c1a4b98d6044a6b4ef2d638eda41a44df9bb40d12a3b2dd429793f05ef2221adf4246ee4e18439874063cd98d22d55ba0c541202928edcb7ef1d962c3e4e" },
                { "dsb", "3b38a7be2c8bafd55a5f7f8836a6e580e2c95f183aa16505e843a101b7cd22e27abd6a3617dc92d6409b6cbfcd29ec5857fef72bdf9a58a435470231837778f4" },
                { "el", "f4e14711cd8c1c7e1869bec9e0250114e71aa2c912eb374aaeb90cd518c128081e1c2252c5cd42ad1a028c8bbea6127e60782f7fd69b88034cb1f3033f69a7c4" },
                { "en-CA", "043a06f3006647593e2f270127e30f0ca208055a86aa2ed3fd9f4b7c2edf12bb09a1e3caba90f67301fcf9269bb4aaa44ca618c64876379d019e4cb96f13d051" },
                { "en-GB", "e13f10441b46ae4d9e7a443daf2df4d50036d3baad6d48ee559050ed42be5bc7c0b94e4073f6eb4f65a3bcb357cff93e73cc40416137e112e9c5fc6596fe6b78" },
                { "en-US", "8a552d7c49aa8c7797457e9ddb714195c8ecd8759d82a0cb9f7f78f692cefbf362efb7f7dea7692ec1024e44cb2adeb43c3c55dc6e6afcbefd8ff5b4f551f24b" },
                { "eo", "36b37b7f6d43d50e944c608bd88e4c370a6c5b56a769b58a560346816c8df9739dba3649c502351357e5bdc1ce2ab3583b4b59714d1d12c08e682512790b30c4" },
                { "es-AR", "ed81ef377b5e906624eb40edcf28eff9f1e4f732c7a761d00fe8922f1c9a32ce2a0d5b64eb490296ffa78ec7780db9619b10c4a402116b506094c0582cc96536" },
                { "es-CL", "38ccd533a296ba93c631434e02d30e1805eb40b3b697c5bf56dce21733f708ab6ee4d62fc90541d630f6618ed80be17697f048459b2ba95055cc116d19e88192" },
                { "es-ES", "0a77ba68e922607a576fea9d81a1c552743827455b2e9404815a9328886d1f0577cba84508aee14dc7f84947b4d89cbeded58c881bf6739921bcaad659ba85d8" },
                { "es-MX", "b2d5fd48e39c355b0c3b5408ffe4cd59295f2e1d0ad8e5a88ee515f3ba1335f64046fb9413a42f720de5de668bcfe31d1e9fbc98da0582fa5f07ca2c970f2070" },
                { "et", "6d9e355e571a94f848c9a1ce402232b49c9578639aac22e90250d281360cff380766455980774f9a3ee76cda1c6c996b08f5517e0ee11da624917d143d6e25c3" },
                { "eu", "4c15eac804a55ec6fe5f1a5596a3e4c4d715aaab9aacf784373f1c42b3dfc491d2253e6e5dbb8b4816b8c4b3bc50f4461ea24d7185ade9b827419bd77bf8d0be" },
                { "fa", "b8c6aa6326ceeacbf019b4e6310e08a9f67fd4603541f489efb24d61378666fcda0ad131a5ca4ecab9855291d2d1c0dd04bc4382ce172c00159f3b6d61a30b8b" },
                { "ff", "02e7c0ec256f78aa61a8f404de0572757a7325088bad5a623f21418806d4e0fa020a441ee0cb5e5021899f0e50ecf9630e476009bdadedff78a8297a1f4c702d" },
                { "fi", "d1794225efda9cce9fe6e312ecd4e422558b428d2149253ef7b3bdd324162a07fb906bb7b0c05f18c44e77d16b61b9d7ca3db7eec82103a49b04f7c98d904263" },
                { "fr", "2c72976dce8c7395aab8f5c4fab5c0e6c00f3f8034e1bf6472bc9f10ad50ced2cf2ff4325a6d222996d28a35489cd27bd0fb988fd383a257805be2d4236ee7a0" },
                { "fy-NL", "fd314740dfb0cacd14dcf04719f39240a0229b3188bc7d91bbde62af1700eb45d51450d059b28f054ba4cc69b0dd35150b5774b35219f8101a6191f804188e88" },
                { "ga-IE", "d32ea2f30090e2c63f299c1e5b16b1b2fb9965a10ffbe33582bc11baa29e4d968f3dba68f321a035289ece87ce98e346911d3221c24cd85705a477f25a1eb49c" },
                { "gd", "fbf02313540fb280eb94b181f6dae8accc789e242ef6012bfa2c1ce593306ecaff1bb26f60f921a856114fd262d856dda04d9be9ab64e896fbcd82003a640807" },
                { "gl", "7ea26156ce5cb9ee07d2e21e55bb21c4f982057d5821f0134c7579efbda46dd6f308209d58de21561eee9f3478709abc1836a929e926bfef4a012f6d52ea66d0" },
                { "gn", "12ff036d044c3bb8aeb8553d3f6b36d68516b154fcb10bc1143dcaf89ddf085bd5027117b03a6d4dd71601c8c4c34f26bbe3e5c08c37c65f383bf1b0465e8112" },
                { "gu-IN", "7e8f3f5f8b31fc23489b9751a93f228aadf759153492c98bd4a07c086dfd0429aec422a0524ff162ecddd74b7243b6e173377f86df3d9990a5423c2d77a4ca8b" },
                { "he", "b32bfed4df0be425372530ea1dd9a4139fa4a9f0d8db78de9ad0a766e211b80891c4f0550bde666c5eaf6a63efb84f85aa663b9f3d885f1bad8c6c07e57b2c9c" },
                { "hi-IN", "6d24b3d573e7a6fa67527e0a864bc2788063145c06d8594f1d160d732a50f4707401a6c79f02046d911b0dfdef6b338cbfd516f4c9dcc7ef6e3cf8bb0a3a1c1c" },
                { "hr", "c61fa506b9253805739a945672fddb09a851150ee68f30e9ef7dd1f24f682cf0ad401189ed24e2186fd233e7849ddefb4036115822f4a9666075e27997f77c18" },
                { "hsb", "31e5b936dcb9cf69f2df5236e1edb24c60b57b4017c0f30a3f0b0500e9265e005211ac2a671854013bc3e202cc24b3f6f261cad7deeb8c3fbec501504edb7335" },
                { "hu", "b937a5129e73bddfdf4e90c621c73c209320d2cce6e550647cb8434c1a9bcc245dc4358eb3a94917ea3b5853b722cd8d19e0c6fca2632e78133a7a57aadb817e" },
                { "hy-AM", "7697a1239957f71f96365827128b0d6d1f41eef0a030a95f50911bd3d51423bfe974c9aeb6620cdefa34595956de75607c6fd758458c8571ade19e550a89a00f" },
                { "ia", "1a0c361d7a9b10b44996a368c4b3120e09b4bea42f347bcde5a6a74910731ab02c01948bee8df800a1d265ff0479b13bf021fd99ce948396d9756eda39609a97" },
                { "id", "e69c92bee56810774bb002be8a1f88ceffbee74e2fb434a39c511a4333507309cd95c0386ba1be70d16009f22a366760482beee1ff381426f5e457106747819d" },
                { "is", "257fdb022cf3caf7c7829c9e05bff52e4d965cafd065fe963e750a49f349dd0a6a4f9e2112549a790b693a88780b92fb547c07eb5a1746d4a4388321de148105" },
                { "it", "ce09227672e986d6eaf5696988599190503913edcf3772963f1f2efdd7b5e575fa83148c201fe7b7bd597c9d21e0e104986fa231ec37f4e4af5aadaf9f61ae4d" },
                { "ja", "0c66c21ca964a6196de366bd086a63cde4b595c702fb684fd54f1a5fd9e8383c85a1f25f4c8baed4274846bb50c44510f6503d3ad1251d565e151b378d401bdd" },
                { "ka", "82446d1d60bfb7359a50033871c6017cc785e247fb2ae703d1ae52d42f41dc75c8c0c63bba1cfbb6da3cabf925966a7ba5f9615efa7d754c15afedc42f99f090" },
                { "kab", "b4cb37a8136932e16b3bd665c076b90582d16a1124ce5cd0045af994f3f30603a98ce01d12b4f562196635958e1356d6918a432536d6952fa265a30333bbe17e" },
                { "kk", "40fc2e3c39c9c07b3c448f7fb38ec6e2ffbc05d2519229678eec48c197a5793f20144e7aec4f7a835a04a371cba70c55b0308ac39008fa4bf557efebd349e5a1" },
                { "km", "8629ea545d0189c2c3099db27477ec7afdcae2620836572f0b4b82943ecf990873afc6986bf35812863bfac6bcac85f01b3f743de77185254cbf56e467a74754" },
                { "kn", "8460d6026dbefc7a585efb2e7dfc7e93a68f2bca01eaf89254cf986eed22720bf00e59a5cea46c2b25cc0a27fad7ffd3a9629241d7a62832f2b61a02cf37e4da" },
                { "ko", "64e223c61fd0f029d77b5a094a29f4ea28900117b8745332b66288aa09e030edf9001353149758660d2dcc901a303e4d135bbbcfef6eecb66030b6b08a154f7c" },
                { "lij", "d6ef1bc8926c9ee32e4cff5cbcd8b76325e98bf912f66b830b0d1f20c43188e1430d091f684813f0dc4cba3543398e1468f2d5bf1d178ff18ad35c56edb105a1" },
                { "lt", "c1d286815ae2edf443f38c665eb60dc4396bad85e449a83882b360c8409ced342c2ebeeba59603598c12b5dbeaed86d02e034c923e03b0cf43db82cf3f5b7ce1" },
                { "lv", "7f817516ea1afff0a85be3247a9449f6baa00cc7ef89c923b0fd9e20189cf81fbec635bfd8c91814cdde62761597bd8bf2896ccd17eaaa3942f4e99ce2b0cc1e" },
                { "mk", "e0c851934fbe303fd59a0e6cd53a1554aca7c19cef03f89336d45978acc2976ddf85c072d723862c9e68c6d9f39566ea9fac33c2a1ea24ec84f71817679eeac5" },
                { "mr", "c47018506ad45d2a6a160d3cb66b65ff2c7425a7d2c0fdf552c7de2a0dd5e2b72a44acea2219ebc29fb36ae3701fd307f961b2e1b5f4de3044903d978087bbb0" },
                { "ms", "697f3538c526002e7b6bffff8da319a4cbe8f52c0ec4c215fafbc320318be577e3f57e87540a8ad256f4a73d1490665350410c4e773a0bd139959dc27342810f" },
                { "my", "9d30380d74690d2d6d8c04b145bb9983f286a308d7d521a4751ddbbf3f56d1e5efcde5ecf66a46aa675c01e2af8ae66492e58607ef0e6975c3404fb1cb31b894" },
                { "nb-NO", "9bca7c6588604b43a6d71215281b7887f18db117a4c86b9c831908cc522afd5ac955f420253585840bb5dd75a76438287323306bb69f8f55d61807f14c5d872a" },
                { "ne-NP", "1265f71486f2ab3cc2a7a5475a89afdde09fcc179b560719d9d8510efe3a9cd93dab42aba3a6a8742f0199ee2a90ec9a182a7c7c2b8af59238790d57827e227b" },
                { "nl", "87abdf4d311c0210f4fbb0aed369f39e39c2819539df18092dd35d586f63ee03c0ea5992e1e5872c1dfe50fe9028ad29a82e2b81342ff148db3916188bb570a4" },
                { "nn-NO", "fbba0dbc345f221babde76916bbc4ca40870cce8d512b0fef9426fae5d2459f3816f2fc87b980ccbd5c70c5fb2c27f02152c14d243f0e2d160c5c33a4dd1d9d3" },
                { "oc", "a57f077f83031b29b325106d2252e0ff14d0b609d617052dc9d415aa28a45ca3aee7a396256b43af99893210ace1ea3f5dfeb03b804c12b7e1579291c470dec1" },
                { "pa-IN", "589e9cec3798fa214fbfadc063cd6e3d95e3b3703e739d0d9d530a902753145a5dab60dc9be6fac81cc1fd0a485745d97d5d00b3d56840c1f72eee1c31186ae6" },
                { "pl", "59c0f5e09fdacb798656aa4d2836cffcbe0656d822ad19ae2101d689e0bff65c851ac3bd2ce9b25de4ef20d8f6b22d82533a6f83fd131f2c71a48860146ed0e5" },
                { "pt-BR", "1ce3158d7a0902614aa209852970fc2176f19511bc9ce53754667f79c2c4ed2eb7f01e72b692af5617c996e740ddc2276a843f478a4f747478cb238d7520d9c9" },
                { "pt-PT", "90002c8d68b31e5fdf3b74edfed8015fb8f5d1aaeb71e3123e66adef7beaf50438f6c5bf9e761070589edd49900885d22be1282184260c1c5c972a57c37dac0a" },
                { "rm", "635db65f7118ee5faf0557f701a56bd8d34d50d2da783377cdc276c5b48cfede39f799c2d16559980ac56345f775eee6bd45b9993fef1e41887d8a8a64462149" },
                { "ro", "9107b8dc906e57e62d609cca3331b177238ac339818b16b0a5dd0cf8723667c1af42cb7c4643779ff285a2dc194b5cb19a90ad41ded3269bd899c323fadcc1e2" },
                { "ru", "9aa1597dc4da0c9e9dc0dee1b7e685319264ac6be7a4c94f0f9c9bf3072b1a18d8d0375941e9600d9ddd3b910cf7cc15b0a9a48693b06c95b212d61d7af31ff8" },
                { "sco", "66318a8e0626775927a4d9c116b4930eda2e013a61eaaa017ab463622f0a75d683d6d1c2ed71f3256ae20db5e7c4d19bd289f541a18aabc747a11dffa59298ac" },
                { "si", "0dde6d5f31eab2a33d36c68210d8c338699ee73d9f4084b31d666188a22577153a2cc42002e416d798de69ee248f3cafa400fd9dd42920246af194307706d2e6" },
                { "sk", "3b7d007b46f250d76077c9d87799cb8bf4374730fc08ad30a614d469fb09c9d7f3e2237b2d06cc98a14182811179da29867226a0d71e8621c95a8a9e663405de" },
                { "sl", "e440eb475f08093d732c0fc0fee9e96e52db4711752ee7a120709d4b5cba908cfcc658f1771c549611f618a86e9347718afb71c00e9adab48705d997edc03841" },
                { "son", "335409cab02dfe52a8e3e5eb2d4fb9dceb0b08d6beaf1fc109e6613c9b762a1d8403c80d9ee29c699b339211feebcba224eb6e9db5e7e253f1ea2095768637ba" },
                { "sq", "6aee156a9305f2acacd139495511b89325ef287851841a2613e3595f4dfbf0835cfb8dfd6125053abf736a12c02bba9d2b468aa06ee7f97b8ef25bf5745035f6" },
                { "sr", "8b83a5246b6b1bb6eb0ea312a48de0ab129d9975c9382379151efc238e632c56ff5977dfd4c7a82edd44621de1e1cc20aa73481f8d58e4868684c4851bed9e04" },
                { "sv-SE", "c3ce5bff574179e0585a7f678d78c71952ad703403eb99f31ffa5446245b8a2789e7f4683c1002fb3b54ddc57b000847b36cb9bd15e74e003e9170d0d310a451" },
                { "szl", "3ec8c1d6b40799f60b462711de5b3b8fd312fe25f620a0e1377bef3ea62424cb0d4be13f9b489022b44e9992d03512d76d9967f1e0429f78d9e3101d2bc5e66b" },
                { "ta", "077826ec2a6406e43a26d0ea51f5f98658afb5e92c807b9ebfe344cfa9a6de439fbaafaddada84f6a05ebdc9a235b6ade09864ad5227c066b21eda6176e68d70" },
                { "te", "7b17ec561849a91f01ac0f783ae1ca02888f7a48810467398ab7043dfe73054448540228b518ce77ad99483125ea46cff1e9080c17305d0ef79491f2ecbbc6d4" },
                { "th", "e28228c540a3e5ba042f21280a3ad08168652017e697396e5ec49e129c73f9d14559d9b08dbb7abb7e032f767120506a1f5c74caad87276055a4dc64f1e2a1bb" },
                { "tl", "3ee92be7a8d4796f0ff370298a29d59ed5e9d3d0ad1b2e7faffc628e9c881d9779c550496484dac7869ef1ef42f8d851d004584f3decce201fbada15f4546444" },
                { "tr", "a9b14ce8fc756c3183560dee9f5210a9f5485fef9e609a23c51323cb5d62098c633d7bf013a16bda077402c0ecc50da9d83a4ba1303b66c967abe731a9c33c8c" },
                { "trs", "a09d3e34ba6067f091f3aa669de9909b50ed462fec32a6330c0ef1403851c3df7d79f72f810d6369087746e5cd56648f230f243340670411f7142c05b9c9bcd1" },
                { "uk", "ded300fd47ac7068695f55603d5cce4a1f224b170d6449b028f11828a7cce2b93cdd32685a175ed726af5dc07424f735340d90668689d902f177278a3cfd664a" },
                { "ur", "38731d8c3216a4a2f37b4b2505402d5eed1627ef28c369cdf69000d703850757389ee671bb8227301915d19c5acdfb78a412cc149b42bc22ab4db3e2cf567414" },
                { "uz", "8f175ffe3d1ffcef03f42b138ba0dbf3160dcedda02f1261accd5c0523ac0d07f1396c69692ffb44e0c28233197eed60fbe068edfec9eaa0e4911722cdf4c84f" },
                { "vi", "994aa9c45fb378ddb11928bd52163b0b8c0fb7c3faada4144c42c0c6400cd852e667f84a78b9638a5f0b271982da66f4923605e32da8b3801539032cdd21d62e" },
                { "xh", "f8c774337fbb7d5020481f3a5a3b6d2e1bdb84e38ece6c4819909a1c9d053608e61032d6a7511eae689ded53d93aa3efc59fbe7a2e4f99dc3afb6be6bebcfa54" },
                { "zh-CN", "91a48c699eb09b56e17c8348ace413153724d9616b307b9cacf377f9fe6265af176527fab7e1e35a2be18af32d98afcc554016a1099d5f65c6c85b76fdcdf79e" },
                { "zh-TW", "500e7da3281babd8cf702aedb5e0db8ab066546ac6e34995cc6a689c35a909cd631a135088120ac99df2dbb0a8ecf55fe44959a999b4553217599ac5c406a081" }
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
            const string knownVersion = "105.0.1";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
            return new string[] { "firefox", "firefox-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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

            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
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
            logger.Info("Searcing for newer version of Firefox...");
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
            return new List<string>();
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
