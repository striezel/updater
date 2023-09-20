/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023  Dirk Stolle

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
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// SeaMonkey localizations that are supported in version 2.48 and later.
    /// </summary>
    public class SeaMonkey : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for SeaMonkey class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(SeaMonkey).FullName);

        /// <summary>
        /// publisher name for signed installers
        /// </summary>
        private const string publisherX509 = "CN=SeaMonkey e.V., O=SeaMonkey e.V., S=Bayern, C=DE";


        /// <summary>
        /// expiration date for the publisher certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2025, 1, 5, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Constructor with language code.
        /// </summary>
        /// <param name="langCode">the language code for the SeaMonkey software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public SeaMonkey(string langCode, bool autoGetNewer)
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
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code for SeaMonkey!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://archive.mozilla.org/pub/seamonkey/releases/2.53.17.1/SHA512SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "977048dfa1c31a8bf90c6a876726f03eef9d87df7ee3ee31bff79d13f23249dcb4a70cc8715b004fd1661e652ee2d82ccc89479a6cd0ecedbfbe54958eccb915" },
                { "de", "f4fdebd31e7d4d543ae6bd6185d6875b85b94a52f36fd88e569f9bb98abef36b7eff3a9bfc9f841c6f28503f871812d0bfdec943477bd41b1a1fb38de33dd633" },
                { "el", "5c97127e3a17d72b5578b2a9ed220e4d474e9b5db75c06ff42a11fa434b5afa52f9f2fbd1a51dedbc4bb2311efbc188a732b8f4930cb4e5cce0c21f65e384141" },
                { "en-GB", "99153e635d1f1669a8ab089b3c3b329d97fb3fdfdac86b578c8bf9f0ce32a1ffa5fe81d1cfa2a3bc99b93d0924cabe042c5f5fb328e5540e6fe8004661900f90" },
                { "en-US", "81a9156458dceb408a865f276017af75f3150b76bac2fa212dc65138b26ea6a03c18b512e96b321f2ccad51a7461f5f43f23a0a140fa2fda16c74cce268608d8" },
                { "es-AR", "92153bff5f7b7ba41a0ec1d6d6c28c5bf56b4736d6a40c43b603197dee8361def0971cf2a60b5afea0b96ee52c0653de6b72f7b528ec19547e5a42bf9bae600b" },
                { "es-ES", "9aee27d80af31af9648bc1d85ce3a3c1dd2cd57acdac67ec3d441fa7418a4d7275b8d38b0f4394b80ad0c9e68fb3f0fe5ded358324e4f53ddbd1c75b02b2a40b" },
                { "fi", "00f8121c819bad7fbd8b8fc9c352d00777919fbbadd398045bc5c90855336721062ddeca8eae08cddaf6d088c45ff7a11d3e94dd7fdc9d7265cd6a8d4081b7d8" },
                { "fr", "510c26d8a15e2cd67d35abb0b2f1c3b3846359137a266cb761e1c7a74eb6949020009666db84c3c312e6ca87b36a7f6a49cc44b39f3626eab6a38e62c4793c64" },
                { "hu", "d595b3f709967594df504674c39578993ac149bbb46ea1132115a4a78f5c924517ab154324ce21da8440d0cb8c323324f11e75241370e47d6b8fad997e7b8bec" },
                { "it", "696c0a27bc4602cb4b19cc412874333001a475bd12199aefaa25511eca415af6734d2c31ca2296800ad8b4eb731659a3a15081e061b7360090d926279112c84e" },
                { "ja", "d7dcba6c905a64736391f0f17420beb53ac373e5020fcc2c8451f85690b75990fd669348de6f485d3a5a8475ff4c58e3f6d3636b78ce29ef076b21389812f28c" },
                { "ka", "4a5290f5428d77cf2ad39cda24e21dd3c72d1bc46b1ff8bc0f885aca482ff702313786d7902da7a1d54e4acedf3db356ba4b2eb1e77e5e882530847498275445" },
                { "nb-NO", "389fa35d2682435e4b98a8c3da9f4b0443265fc374d0f81c2ec8ad87a56e2e899de4dd4ae78a41a7fef8510669107d3e08e4a50091fdb00e6d67773a09104953" },
                { "nl", "e816b07e393aea2d15e15aff93e4a5ca5fd34f2c934fc1bcabe7d0ba88673780f9cdcb7142cf975d7700a93030d9c0106be8de2af6658a9d0b36bea7e143b882" },
                { "pl", "27a61ccd25176b9747dd7f5f73bb2e5dd2c018909191c91539d5d91fecaeadf7ee8d5cbfe542a07295ff4bf083dbf9c630ada9df34503bed12509b7bd8ab2fe2" },
                { "pt-BR", "6bcbd8749e7f5e5ab019d14e2f8b27e16d388509aae43986e1298430a43e90036803bbd0b69b42bf8309bfa27482580adc0caf8442a2e4333102426e260f3b0e" },
                { "pt-PT", "a68aea66f904a96d99a46e6d24e9f3dc6bd0903b6ce3dbb678354cc0874dd5efcbb386e1ff4086beeb4b3317aebf6dc0a13efc3cc11354666dfa9cf1fe924824" },
                { "ru", "17562b589226e5b68d6dcadf1c4561e17332f3e25ae7c8fbe33872557971a06bc4c85d7345380ba9e932f6ab4b358a11606ee610f2fa0d865c797507bd8516b0" },
                { "sk", "a4ad2995ba0ece095bfe520bb9d8ddc49d03daffbd9d9589a85c65087a68fd25930e0ef791a96b1f153338310525fb301e1b7ce1253228c3dddf53094bb4a7dd" },
                { "sv-SE", "b3b222312986b3b0e72ec0dd7e4e0c883db2bbaf43237f38abbb2adad0b7fb96075d878881f666b5b8b34ebdfafe94f447ea0ad5cab642f53a0c2bd682084fb8" },
                { "zh-CN", "c4bee20dcdb6e82325a7f1839a0ce4e634ba90a71c203a620e3ea4f1f105a4a57dc4788b5d38dc8c4d14be8fe92c4fc7e78b128c352215515f1d9e9ca8e53895" },
                { "zh-TW", "6db9f08d01d62093727808595bfd2074db3a4ca7c199ec587db642d553221ac23e1f9e79bf8c5c0653c7279137de55c7e631318e6e814d74974d839707ca03bf" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://archive.mozilla.org/pub/seamonkey/releases/2.53.17.1/SHA512SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "438467fb26922376f9363c10c6080e23c6fd12722a068a13fada60dc2f0c989954b1ebc989fdba246f976d2288d826e87d06a5f679c8f308b12ca6adb1e7c683" },
                { "de", "4b711e1c15aa89fb8271d3035c3bc75c4e9ce8826c237ed337a767b2bf9703764a7c046b940d3424b32b39b7b0ec4af91afff88303a91c5cfcca64d08396a7d4" },
                { "el", "e19eb818a49819fdd2f95de80a11c51d7f1a7bb38723cee150ae705a68b5a6ea85ed72043a4d38420d321812156442b705160b17f5f5e8a8251eae720428b602" },
                { "en-GB", "ad3488a82ca69ed28a2c8bb6d3a334d9218fb79524ddaae5a4434475a7d029e61f31cc3996afeb7340e44b00719bdbea4225b25f6b8561f1fa5514118b5d440c" },
                { "en-US", "7a1d53d97b38b9bfcf9fb8a6324d1f560dfd034c7e0985ac7207a165ed243eaa0dd031506eb1d780a2f46b3f0d746e2e9329aba4dd9a67e44568c0b773055f2e" },
                { "es-AR", "f0080fe9f97d50aae83e58c824a943fa66ec67279e4dcc39ac74787a0bb8694b65537ae1e8ccc3fe5de1e73e27846536df4b36046d0fc54a668a270c2055378e" },
                { "es-ES", "394d5660f491fc031738060a4a529c654ba6f6f28b574475339516cecde533464b1f025d33f2e7389ad1e29746e4227ee7cd8e99c84785217a4d37a282b29a55" },
                { "fi", "c5551876225ad039532afd21a8033903267148fc7310a1a2f8ccb0b1612ee3a08848b09b025d81b8a9fad928f5149f8ccd0827e7591ddfbd6ead9d17398fb8d3" },
                { "fr", "05d3f3eb4139cb1042dc1598cd57f1c175921f3b3a6dc5c36e2df6f92cacb9aac040c96c515af17d1b7ec00415c76a8949055bc9bba08f5443ecad0e5581d06c" },
                { "hu", "ac1b3f0447616500da9258178abaf8935d350e8094ff8fa760812d638cd2378c4bc74e9b729a0277282ea2f182899fa5fdaec071fcf64c0a6252181d24091e36" },
                { "it", "118e7ea2440e8f0ca8e3922c9d2037671465405f64273fe1b254fdc9fb643379ff966508ba376b303cc35a20ee4c3d6f28f66297aa5cc9d1f50f34586795e8bc" },
                { "ja", "54cb1c7905200c33fb73de63a80fec078450d525e0a79cb5de345fb2801ba1f0089f0ceb8205298d1791d8e20c743e3cab1269f6554c83e3a27a996665c4515d" },
                { "ka", "9639848b9132648ea2803a1b0c61856c840fdb36fef4ba1dba0319573bc7e80f90e03a26b938f3fad8d7fb07e0006390ef58a64da7cf9446a5b861084acc3301" },
                { "nb-NO", "3622bfc5d9709c9ca648d9c5470772a26ac0fcbed2272e6ee6e54ecb6914766bb68849df0d6922844e9ade92dbebb9e2a3aa741c350dec46ffbfd72286addbcd" },
                { "nl", "e6e19c8e0176f111d555ae97448becd24e5a8a431b00fca046a0e7e87d9cc033154e732b4078a3c9f8b97f4ea6db55f5fe0ab374b6281f5efbc043b49ac01b95" },
                { "pl", "487dff9ac1746b1ec6eba7fd725bb0c1fcd8c7290d63e662f45bd5475bb76dd959f80f76c11c1c8f8d84987861712b6d5eefee00dc4984fbf27446d800883ed2" },
                { "pt-BR", "2f7290f8a65b7274d323dfd43469b705d5108f1be44bd40dd7193eed4727c136fdeb36981f55dd642e7b17f5ad38df0584e66a28fe33de7f0533605f51510035" },
                { "pt-PT", "445855fda3c7d2b26582c29855c3d33d5cd12c1fea1563b686bc55ad1c16e33b99eb40e6686f6ac5705af8f9a9c3e0500f5cb789570110a450c82c8030b9cec0" },
                { "ru", "b0f1ce5d3bf1d0fcae89f3c554ab109921a9959dd27413f63b127266a1f4a569f4b50f0f69db857286af7ee3a655f555c82796513beffa3277351cbf5cff4930" },
                { "sk", "cd844e4580fb5b48e60dcb69b4ddb40aef92d859402ef7d2fb90fabd0d55a98ecc3b76eef38ba82e44f9c65ea8492e812764ac68006e6196d247f9d387cfc044" },
                { "sv-SE", "c45bfb399a2c1637f156f7b06dab116afaf5e21d55595c4317aefd9b5ea9a38024340a20c44f0696fb4dac55daab67f10c529bf80897af50537d5f819e9524dc" },
                { "zh-CN", "f2351502f05bf4dc7c38e32826756ec15062f415c8f4a2249d61acd9fe11a3fabd6584bcc1d75b0ee10ae99a6bcb840d06a49534c3db042e421cd2c10bf5e5cb" },
                { "zh-TW", "6e181dcefc00f8919b5e9a1799b7133df21f697057be8c0e4b6399063b2d9bcc2d40d045f74e84c741228a8e754e026b7e3709fe9494f9b9f9d9a9ff344ad114" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            // Just go for the 32 bit installers here. We could also use the
            // 64 bit installers, but they have the same languages anyway.
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
            const string knownVersion = "2.53.17.1";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("SeaMonkey (" + languageCode + ")",
                knownVersion,
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                new InstallInfoExe(
                    "https://archive.mozilla.org/pub/seamonkey/releases/" + knownVersion + "/win32/" + languageCode + "/seamonkey-" + knownVersion + "." + languageCode + ".win32.installer.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                new InstallInfoExe(
                    "https://archive.mozilla.org/pub/seamonkey/releases/" + knownVersion + "/win64/" + languageCode + "/seamonkey-" + knownVersion + "." + languageCode + ".win64.installer.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "seamonkey", "seamonkey-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of SeaMonkey.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://archive.mozilla.org/pub/seamonkey/releases/";
            string htmlCode;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of SeaMonkey: " + ex.Message);
                return null;
            }

            var reVersion = new Regex("/[0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)?/");
            MatchCollection matches = reVersion.Matches(htmlCode);
            if (matches.Count <= 0)
                return null;

            var releaseList = new List<Quartet>();
            foreach (Match item in matches)
            {
                var quart = new Quartet(item.Value.Replace("/", ""));
                releaseList.Add(quart);
            }
            releaseList.Sort();
            var newest = releaseList[releaseList.Count - 1];

            if (htmlCode.Contains("/" + newest.full() + "/"))
                return newest.full();
            var trip = new Triple(newest.full());
            if (htmlCode.Contains("/" + trip.full() + "/"))
                return trip.full();
            else
                return newest.major.ToString() + "." + newest.minor.ToString();
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
             * https://archive.mozilla.org/pub/seamonkey/releases/2.53.6/SHA1SUMS.txt
             * Common lines look like
             * "7219....f4b4d  win32/en-GB/SeaMonkey Setup 2.46.exe"
             * 
             * Version 2.53.1 uses a new format. Common lines look like
             * 7ccee70c54580c0c0949a9bc86737fbcb35c46ed sha1 38851663 win32/en-GB/seamonkey-2.53.6.en-GB.win32.installer.exe
             * for the 32 bit installer, or like
             * c6a9d874dcaa0dabdd01f242b610cb47565e91fc sha1 41802858 win64/en-GB/seamonkey-2.53.6.en-GB.win64.installer.exe
             * for the 64 bit installer.
             */

            string url = "https://archive.mozilla.org/pub/seamonkey/releases/" + newerVersion + "/SHA512SUMS.txt";
            string sha1SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha1SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of SeaMonkey: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version
            // File name looks like seamonkey-2.53.1.de.win32.installer.exe now.
            var reChecksum32Bit = new Regex("[0-9a-f]{128} sha512 [0-9]+ .*seamonkey\\-" + Regex.Escape(newerVersion)
                + "\\." + languageCode.Replace("-", "\\-") + "\\.win32\\.installer\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha1SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128} sha512 [0-9]+ .*seamonkey\\-" + Regex.Escape(newerVersion)
                + "\\." + languageCode.Replace("-", "\\-") + "\\.win64\\.installer\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha1SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is in the first 128 characters of each match.
            return new string[] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
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
            logger.Info("Searching for newer version of SeaMonkey (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
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
        /// Determines whether or not a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
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
            // uninstall previous version to avoid having two SeaMonkey entries in control panel
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath , "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the SeaMonkey version
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
