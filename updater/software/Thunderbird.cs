/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020  Dirk Stolle

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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d = knownChecksums();
            if (!d.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum = d[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/78.4.3/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "4c758d2066944d89adfd759c15e1b719b081048f476f2c9dde9d6ccb4580485c1607e4df9c6f7f163a31437a3fa1ef7a71487bb09bc7245039d482643f20172f" },
                { "ar", "5438eb23dc15e83bd6194ea9d048633070296702bab7c6c9d0fd62284d79bf86ec76df7ce4d75c14e6aaa071e383a884d158954658a464751f79f792a53490fa" },
                { "ast", "921502a373bf507e1cc6b17c6ee0634e932ea9daedd77ac266aaba55392478b5f44d374e89f293c99c0c5a43a6525d90d95c0460707c0abcecf39393187c332d" },
                { "be", "e6e40a218d479a40c59c940f9c3aca65e2b0a6e23faa641935bc66d1d1b52d61343c1d047e048614b47b90e592130291168f77d580b03cf168a71639b4756eaa" },
                { "bg", "02fed762fbbe903b68291eb06ff2bc699144e816223f956987b7975381b17381ab24849bf2e7f5ac85f254e24f05054804699c8a4e0d840d202ffa87259820d5" },
                { "br", "445d1ac5474c87f4c8ce917598250ad4a8a16a9b9596f73ab9d3b26d2a5daa2c21e4453b76208b82f491d687d068ba66478e0cc0f1efcb500e3a330c96f74519" },
                { "ca", "abfd9dee21fc29e7367eda3849718cc39b05fd63f9dc22deda1ea31cedb0fbcc7e944751094a9459befdb0229a8b9971b944e0aa4cfe9d53e5d9413a3dc5015f" },
                { "cak", "5a229329f376ccefccca9752b36f577023d18d30fc8a4b7c895bfc2ae14bc04788bf2a94a13f92d97283adfe90fca687e1f1d70550bc01b70d0dff61711acb19" },
                { "cs", "bc47c00b7348e9df33c52a5545d5c2ebe6b11de88621814857d856c71175c2952b00d37470ec02740fdad618c5ecf9a8c1c1635bb6b8b8ee503e12e39af86985" },
                { "cy", "5d2dc62bc9b62eee189c8fb2d3af0f018c68b25a3a01251eb5ccf035a66401be99f15a2ce249dd25984545d94487e421502c39c6e9acc1cd14b0185a992c824c" },
                { "da", "5c1af611d170eedf64279225d1efb1ca8fbb269856307dc9286ba3adf85b108d6adf1a1d31f1646246c68eab1123f264dcb36c24b812dfaf0f8d2cd7f8ebc8c5" },
                { "de", "11cd249189e5f6d838e7aad413b915fbd8f040c764bbc2da95659614dc88a0f38fbae1e7f221352d5dcdefca7ddd4396fab353a58c147768b78e22513fd71de6" },
                { "dsb", "3172d55c63c11c3b943e64710e52268ad7ab8e4ea0fd9e4b655d6f44f414f82424dd7c23dfa335bc261d576bfebbb05a0e1f50eff650407bfaf2126349847330" },
                { "el", "9c54a25f7c6ac85bbdb1f323eccb248091050e59df6da183d31ed928e8ef01cf324e43723ea59be01ae2014eb0ac3f28c05c31e777e8577cc02b5c4a86dbd7a2" },
                { "en-CA", "24a987b57b1f77f30f0f939b77715a2029ca076c59f9e5da3b4460affe3d7a9cba6ba3713de8eeb32a54e00afc0063cf62c866de394e20b9792c00db2c3a96da" },
                { "en-GB", "13b49632c46ce9ddfb13be4e3c9458b7f50e4ce9dba5620ae2be2287a09ee2fce5583a5e9d4f94fc2c9e5233ed0271ea5190dbee8c7d7cfc294ce87dec425dd7" },
                { "en-US", "c4b1736125308fbf38072645c4f0b658659d89b239b103f8dd95f4b99ddff10d7e64969bf51d12ba7c6b7bfeb77828461bd82dc43cc1c17fb20a2b363817abc1" },
                { "es-AR", "dfaadef5f22a7e6bdf095c548741889c7dfa526f641f2bccea79614824755ee47c0be8744992d59c9b08e7b60246f759115d3e734987d5c66348fb507ee8f977" },
                { "es-ES", "f59cd95b220797a2e28842c444aaa4f45443d7dd809cf0bee7b886eece63262788fdb633cedf47bd7b9c3b2d88b67b337ca8515115312e180176e31b1924fa3c" },
                { "et", "fd49b7516d4a0b35937cbf6e2b512d32af3c895c95fc79f4642b785259a472368112e1fc83047b4ae284ccfae1888dc1d3f8ff880676a2a0bc19821f5c3d3134" },
                { "eu", "3004b10bead74dccba1b27902b526b40a2ed1a3c1806092c740519ce0126d364708998b652c34b53beff225c0c1044b47b951b6ff889e1793ec58405011c3803" },
                { "fa", "d0b097002ed09bf36749d1d8f15c52719734be1c2baf0d0b210d4050e15db0ba2c43c0308e4ac27ae516c3ff73d6bb84851c0b1ee95567b8072651ac9adc5e45" },
                { "fi", "94a7a0a0288e98e614b69165bfd960d94216f86d8df37971cedb3ef81ce24be126ca306d99cccdfd48998d1e6cd284edea57eaae58d1ae2277218e2b3c00d34f" },
                { "fr", "771a6ca500539ec3fbbdbd0cb7d0b21226680c3213ad4d227951d96f5c86064d4781d83b05bb0b0a9332e096edbccc04588d4acc14d7621c0f3f55c20c0904dc" },
                { "fy-NL", "5e6e74f9acbad6095ba8934c478cbb64a92a08b4b2077387b4f1b711c7449d7396894abc149920f03e55a18b13b609cffd7760134f170cf0de50ed3587e08251" },
                { "ga-IE", "a0a60c309b2c44a382c0e01b006e28b0c49760826f18dde57668c83347a7c852b751bed346afe2e24e56cdb4c96bfa5ff3d3d6449d14f98fd4bc93df91dfb7af" },
                { "gd", "322fc2b447b55717b76ef2385ddb749cd5ae1b7f50a6044ed16af98f81b845a602eff74ae04e6c6f1618c00bbf5799a6666fdba546673d52780bcb4887942927" },
                { "gl", "95f784bd4daee05a79479f166b0e6774871a930466e900269438edfa7ea8b5ca12855de37b00b76c3b1efabd185962cf43e293dc77ddc12e77c6596a4f509920" },
                { "he", "9695316b49574605dcfa5aed339c494e810ec36d76c034a0cb1f1314e4d1799fb5c11129f318ea8938fca74214a18edbfe1bf88219c25a8d910344d60e985eab" },
                { "hr", "2a247af2a0da502947731821284c5db97f36b543f163ad3382f2ff9ed5a6be8acb13711266f812a43443d0d41018eb901991bd9d36a714a46f44f331c260ae04" },
                { "hsb", "120eade097217e1a7e5f380577f9828282cd3c751505bf940b6354269a77bf9835f95967f7a3c8769dbacd267f87d8f154e5056d5e593f669bc063f05a39bc3e" },
                { "hu", "41c6e4848c93a2220c46c2cc112cbc3850eade563e2eb5da4f10fa10f04332843c96465bd7c4521a1c60a57a34a545740ffbae3a9bf426d5288b47565e69f456" },
                { "hy-AM", "e6f46f95639e61c69212ceb917a7f03a1f48f2d86cbef9f04fd7fefb3be256bb79ebbba28cbde44351b261fee08ffa9ebf12f084efb3e9351ddd48fcf46e383d" },
                { "id", "772a452facf707cd3eb73715aab8c3694263b399d31c478836b526fc7585aaa195bd3adaefcd13923ea54835a59e44b7492ff7c883100e8ea3cfd087cc850847" },
                { "is", "6b4c28076275b43bfcfa557721578c51bb7a2822cffa475bee221af5ca091b8cc40f2de1ff33269cb3f9006e0647f6ba558fef0b210d22c7f9ca249e0b7958ae" },
                { "it", "26a96376c9c18ef1dc4f662a76e5dfbebad251b00cbd0434edeecd3c1fef29b29fb117cbb1517cfbcaaa2bd0a29b81285ea4148d7832fa351abedbee79303f92" },
                { "ja", "b999fb6ca798e0974dcc5cc57868f9fd00fabe7fdfa0dc4a53b83d35521d816b533057a1359c006477af908a38fda02e0fd51a4f576e9d2dbe43f657d341fd6c" },
                { "ka", "69b4465819199f3f1991f4f53c04aed9fe0f2ca543bcb5489276fab6d0907b7857c3e5123b5bdfb55d81aeae1ab01cce56b55fd85fbc17007cff797b208ea463" },
                { "kab", "ced633d0ea3b898796049ac89ddb873805c3d970f2ff3beb615168432c9cb198022f26dc8f903eacf59b3a08d606ccaa6d51e60dfc67ac72c97126c984014726" },
                { "kk", "f49b027b2639a6551a4f79343f3e787a8c0c862a3aca078ff171a82c892fab900347947c72a94323fd00781f628d057c887fa064b8ce2c0203e0232833639915" },
                { "ko", "e28d20c8243cccf60ae445575835111d8c957f257126d0f47287ee816bc4e9ce3883d44cd18b87b6dfa3d251e72a20bbcee7b7d598a58e9221a5a16bd35508a4" },
                { "lt", "ac07b1855aecb4a479d71fea96d41ec7142d05301b053adffbc086c3ee60ee91843f23f60020c6366523006d8f70f8320a7712832c309f25db65dee6f7548fa1" },
                { "ms", "2bec135b66ddc2d45da746790cbca61df2186568b8ee96b5bdd5381c10c85909637ddb1216aee1baee0ad290f461f6c41bc2c39357369b735b4037c5ed91b01f" },
                { "nb-NO", "cadaf896910be8efe65cb0dfe4b026ef7eb5f7cd3afe853b0611b3beec40cfade74479bf26ae0c717561623185453fe482a4fc7453d628edcb6d58ff41bde53d" },
                { "nl", "d1d943012386f36ec98f3d226f43477918fba58fee471514c40b3a7042519e5f4911114cd9e2c20aa3e4bcc28ceb2e6c6f445d9470826ab22875d67a3b4570ae" },
                { "nn-NO", "071a69513174ac6d41169dac08f23c2cb31eb3631f4fde5a5da8aa899d5f709131433aa3cd19198c4435f98ddc0eeb36d92d66c5d0ec06c854a10e87ff7e9e69" },
                { "pa-IN", "20b2b90536747159011658955d476badd4d2f8443a2cb5554ce918121e0927ba9cc1b0413dc755676dac9e2667b8facb168899705582fb5fea6031250526fa47" },
                { "pl", "0f18414c71c7c4910d1e491de27969f9fe8c222d5261aff0ad447334b9cf24f8d41b390c3723418715160d911a14bce41c03e46f267c2915fb19dd86b61503e5" },
                { "pt-BR", "9f7f1368e7eca50959a4e37a901c5552ffb0249f9bb5dcd1b632ed3c8a710873e8a757f1ce8b9e93f2904e3f26c07cf751c4567401e705212fe3ffcd4a2a17f6" },
                { "pt-PT", "c9ae793d81285db0993eb94aee2afa8db6c5af638a3f18018a10806cdaa6231696d74f0398d6943f7fe37200829aac0f8312e5ed4d44744737c3624b1d08304d" },
                { "rm", "eb0b4542b7d115520ff96603ab8ff2d5c13b6bb8e80b1a7ae97359dd82b4d48b9a47636aac3e3a8df79d9b905627645c690c017ca12f5f44b41c908b3b6895da" },
                { "ro", "e7a0816abdbf1a7f8144c31ef365a985ec5aec31f27bc91a7a4e4222e370b9ce3a101119b003ec5b1baff9633e07a76fb78cd6ba9b119feb9ce6516106f67564" },
                { "ru", "6589e07e788140d9b15b5e58fb3a8be10d46f10203557ede51d8305ff67101817c6d35a01e2692255809d0719ae31b81efea82fd0690dd44f883b9cd1482859d" },
                { "si", "f38072ebab641d1575fb8ff77829a067a3441859e859602eacfd7a12a21299620cdbda0eb9b16317a31084597741ce95242375ec48e2cd575b0c50ae503d6945" },
                { "sk", "f4c51d442cc4d19e46af21cdd8fa28445a0e96025dcf5922ec57a5cc3b2c551a47122a8579246959d599aa9500b5969fa4b08280dcf702c6e23fc170f5836dde" },
                { "sl", "e3b159e8f751e2b782d76bf2a2a29d308b9cc29f03bc6277a1478e3396e5ec25c68fea0dafda036fbf022bbdaed61ff1231768fd8c7fdff06274e306224ad7ec" },
                { "sq", "6a63e7c3c815b4b4ca5c36a7ca4e37595811bed7c20b4c771af6d8cc09ef888953f7e5ee4cedc0b3844014590e84fffd059be590178d9a25059003ce0b86b763" },
                { "sr", "34e8cad86c00717756f7aed1488e0ee13eac42017ea37904208406893de1dd4c6a7ac70b10b8614a84d390c4113e06afa33ccb12380f2eece84932d2aef7a5b5" },
                { "sv-SE", "f70af157bb98c3ca49a4a052ed5438c2149483ffc0321df8b4617cb9a91df7069075854a5187cdd58fcf3688cde707e96a5435a8dd7f14668dc2d474b8aa2e00" },
                { "th", "537b32ec9e7067ecad64fc880cbf150bf188cbb26892ba31550b05292c07f5d9e9e9a3c7671193a9a5cf47695398d82d78f4a3589d1dab4b313db8db88229241" },
                { "tr", "29c8c875cf54b3188a1e16f866bdccef92f0aa9c1a40a815b7a22cea624ce42ceff2839fbf5dadeb266c9f0ceb2fcd43b129c7c3fe307d09feb9e036340d7583" },
                { "uk", "48adeac5b0f0c8046ab9a8dff27d0d619dfff6884a1b5f051e92bc94178fc55cc5282db6fe9c6aef1f90f02c2d9275400950472d1e4963501978d3a0d0430b0c" },
                { "uz", "5dda948770aa25788b65b03d40f50ab36276c27f5c55a37d346d5b3ffab9c3aefb210485686cc698e04da076dd0bd06deeb7fa998f2b4a8fb0eabb1779319bf7" },
                { "vi", "1aa2c10592410236dfc1cc7d4390f455d30085bfa547f4080b31ded370da3f53eecded2f1b232114a2fe1641a9764645bbeada21f7d001809257fb198ab9f135" },
                { "zh-CN", "2930db1ff637b2004a36b23842ac350b8a860f769afc5c3c626de9c420ef9e7ffe0267aa4f2cc9c0d4e59da6cfb5897640fc24b3c8defb0189c64141383506e5" },
                { "zh-TW", "0c11c21b9a844eca409182c2a729ef90e18d5bcab1a3343d433cc53c45091daefd0d8ad28e77db0f1992a2f08ec1d5ce5a3ccb6a5ee13bf50a9e1040a39d80ea" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string version = "78.4.3";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird [0-9]+\\.[0-9]+(\\.[0-9]+)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                null,
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum,
                    "E=\"release+certificates@mozilla.com\", CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US",
                    "-ms -ma"),
                // There is no 64 bit installer yet.
                null);
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successfull.
        /// Returns null, if an error occurred.</returns>
        private string determineNewestChecksum(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/45.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } //using
            //look for line with the correct language code and version
            Regex reChecksum = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum = reChecksum.Match(sha512SumsContent);
            if (!matchChecksum.Success)
                return null;
            // checksum is the first 128 characters of the match
            return matchChecksum.Value.Substring(0, 128);
        }


        /// <summary>
        /// Indicates whether or not the method searchForNewer() is implemented.
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
            logger.Debug("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string newerChecksum = determineNewestChecksum(newerVersion);
            if (string.IsNullOrWhiteSpace(newerChecksum))
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksum;
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
            return new List<string>(1)
            {
                "thunderbird"
            };
        }


        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate proess returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the installer
        /// </summary>
        private readonly string checksum;

    } // class
} // namespace
