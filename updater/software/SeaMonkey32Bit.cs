/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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

namespace updater.software
{
    /// <summary>
    /// SeaMonkey localizations that are supported in version 2.48 and later.
    /// </summary>
    public class SeaMonkey32Bit : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for SeaMonkey class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(SeaMonkey32Bit).FullName);


        /// <summary>
        /// Constructor with language code.
        /// </summary>
        /// <param name="langCode">the language code for the SeaMonkey software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public SeaMonkey32Bit(string langCode, bool autoGetNewer)
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
                logger.Error("The string '" + langCode + "' does not represent a valid language code for SeaMonkey!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://archive.seamonkey-project.org/releases/2.53.21/SHA512SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "392b9506fd2debf73c33dd1bebc11ce541d1442febf36deaa98d672b2bbd32c94c051a3ff560a5a8d851652e01de4f6f2347866406c4238399a430aa5d640299" },
                { "de", "507da8769920845cd57d6c7af5419fd3c9a8d384c133b667167f8ed9faea004bad73a03ba938280a7baef1ab9e70cfabbbbeb1ea77aa4d75f83c3f64ab4154ee" },
                { "el", "8baa721a32be471920ca91f900ee72cbbab9f40ecb54a1924bab955fe80370a1f617bd76762fb2600f7eb68bff2125d932253b777a08e2dc6ec7feec32f3e134" },
                { "en-GB", "97c299d4ffa3abd23e05762ace3319343afca492be06b0df0867fe0588495d861070d719366d11bce13e15809a03e94b8253a996d35b300233ddf058263cd86f" },
                { "en-US", "adc7b6bbdc15065c852eea98707202ba47ccd35074da1549e29c7f91e0a3a585eef5aa7ed6cb46c6ae8456d8fdd3a9b3ec684347fd26c29ae826c83955d25b6b" },
                { "es-AR", "82a0e35b748d47a30fac062e995f691441e1c3a7a071d2313f5115eda099e8e2f8be484e4c639fe6350947babefe3c0b30093029200bfec35cccbd4eb5ba1d2b" },
                { "es-ES", "8d82f643311ea59990161d298855d27f0015ccece76853af8f7e4bc19cadc93adf44412f3ef8582fb827e598ab84a9efc27d414fe864f3a36b7795f7c1282fd8" },
                { "fi", "b58bbe85e0a2b9bcfc0d4a6800a39e6c1a112468004e0a8cde5ba38e15d9106b10131dee3cb27915d8d7d24a1bc541faea645bcdc6f7230432b1edf98532eddd" },
                { "fr", "56ea79692f37189445f59d63d681f3b74e10eec0214f31a4d2776d6ff0e15ec6a45150f6700d190312749e6e856c21825362d96cdcf39c336217e71f7f002c68" },
                { "hu", "b4bd42a2d4a9cdebd382efa4d8e0c1d388143d8c7fe41cc8055ac1165c9248ef64ca5d8629fc3b8fc0e498784c57109e52ccabc200f11834559cf6ad370eea45" },
                { "it", "03ed43a614a8fb0369a0e82d2592544e0edf12965e86794c4e03d0bafc30cdf618cd29d3b60d5d350a9c454d73f9a45ec3948970dc5b51f478a8f97c737229c4" },
                { "ja", "058a64ebf334cd3b0217b69df592c67482cf5d732082a77c4e7e0986a7d061cf495a37d820dbc0c0daadbbeb61aeaa35f790ecc9ca2a0bb2daf4df363541d36b" },
                { "ka", "ed0827cdef443f23b6f21c2ffe12b66d344550105d31b04112da337ff7f91a019fc1c52ad3d6bf772604c322214e1964b6f2eb5862565867488275eba5b6eeef" },
                { "nb-NO", "9a0ffe6e7b0e7ec90a2c0e9920734735e5ece8b245f22af87d3febcc46cc5d0e1f6c015826f2f95b9ad674147572a89c7c9b0dd195bd74305ef7ea188f2a9519" },
                { "nl", "aabcf252ba6334bcd31b5400a2061fba80afe1dea129eb526ab6b3af312fac101c1c47756c0fa5b94980e4d53f14c18340ed3c334fa315ecfddf3de52e9268e8" },
                { "pl", "c286de4f21f6f70f25f4ee2d0e97fd2d5f82b9c86405975cae2c3d95f58e6a24afeacdc0327fcab97aa6785e8e4bde303816010d8d46c1a339196e20b1d0f441" },
                { "pt-BR", "bd89ff40f6b229459499490a6a8d72928438c53c24c0fa2d97b767ca8fc7759f50f3de1b3ed987e118517bae34401d9c8a1a44cbdfca341064d66d6d8f8dd714" },
                { "pt-PT", "333408d71a884931565e085025451ec4b6814a63b35c6c4349e57f508d3e1bf598780fd462eab8af50367453e0e88526e5f3da232f6e4bf196c13d3dd8a156f0" },
                { "ru", "eef943f3c7f4ba956383c18126bf3ac7cc7a62d4fe0b6bb088c3fbb5e83dd9bf8735bb93bd451beda579e8dfcc7bf59d5c40c8c298645afc37dbfe186561a1c1" },
                { "sk", "8b514819279ed6e6bf141ff50871a6b4ae538d7abda6605af080ac5f17c4983ffead1678100de172aca25a9908f0390d4e73990bd28de87b103ff55c87458dfb" },
                { "sv-SE", "94696c38ef5304a1a6f2703d2052cbdfaba5436ddab4b82a071a754459243340ac6efd1b05a5e1402e98506a24beb94f9c203d201399f36370387db5e63f7e08" },
                { "zh-CN", "4a385446ed335aba863666e843ba0f0ff81c3e6d179f483b37d8dff0dd4aa6d2709a4c58c600255f3dcbe3d1acf2c2bf3dac4533f8454ee21be48fc44366ca27" },
                { "zh-TW", "733c11d15ddd2d66a7801d92c9f125557a0ee8587fb433565d1711e51c62de2f087121879394790161ba7e55beb25e11ad70db2bafa4b4eda639dcf447cd5e0f" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://archive.seamonkey-project.org/releases/2.53.21/SHA512SUMS.txt
            return new Dictionary<string, string>(23)
            {
                { "cs", "3845f9adb9b5a13a5cddce1ad51a60aacce7de194d963ff9b4eb130c5800d8afbe83a1b5310014a3dfc1527c644271349e12de91491defd0f7f369af0a049e71" },
                { "de", "1aa934fdb4a7f22449867dc67178b5dfddd756f5768123b3bdf98d47e2051223e5fa9453ae316474ef674b92f35c83e1b4f5c60de80175c1a61025927fec4dfe" },
                { "el", "fdf41d6542164f72a963a15bf6bcd73f9c159346fcca3ce86a92372722322e6d7fce26ef67e27a79cc3654b88b92147429ee0382b5af355764ddb0184d9f3273" },
                { "en-GB", "4004bd06d317107346c4caa82d642c78515625972d151454038a6a2526db8169b8fdd8ed03424e58e8cf7754d4ae86c73e4d92798b33a69f7cfad3c6991034fc" },
                { "en-US", "26ecd7807db6cc6f192bc535602d05f3b46ac18768213ecc318dc5226e71fdaade6619b6173b9cbf36f60b4cce0250e48fe16ac3e1f48f773dbaa758317636f6" },
                { "es-AR", "aa817dd83e42dc24513b6d8f9d6039e574fce58ece5cfdda388494a55430b5727623c1a60e9c48d4cfbf185d38eb08be6d73a8f332887c025a14ff202b94fd1a" },
                { "es-ES", "c666faf93b5e5e8411a02005d1ba6f1585fe6627c4b67a329bab255b69aeab591d54f23fb6248b6962c86acb96b2a4748a67263dbc14106625385ad020740a7e" },
                { "fi", "0083c540224698e6bc31708f1831ae1728dc50fa4e91e9dcf4d0ff85d61c9b488f806a6e0940f1df0c82bbbbbe07e802f1ef3d1e48573b63cfbaa42b551d4ea3" },
                { "fr", "d138a05bcaddc661ac4255daa3c3f6caed5f82722b63e8422468b8c097e0009fb0c1897fa2359df03eee4140f612318a51c99b487a788eea741f1879e8093669" },
                { "hu", "6594711f4ee529ea6d97ded970f1b75aabdc5c468586de16e550e7b08ba29454fa1ee8233f104cf1d3c76ad9c58b1b1e734b11261a78fd53d044b9246b348ded" },
                { "it", "9f88d93c1b18b9fd2677643945a2949cf45e74beb47968be81b28df5c8e0586b0b6bfdd42fb2717f3a94e421cef330569a296d775bac010bd07e399308b92c40" },
                { "ja", "6ac4e107945a9f765dde87142e4ee085d2d03d0f17b64a1d3edaaad5fa234b07c99b237d4858dfaec3f465029a3049cf8cc5b0c8c546774e256dc0161db9c601" },
                { "ka", "7c3658306375764e015f2814fa353206868505f575cfdac75d69e53f9c579708505cb325bec17d2d4cce15b57c7b3863a7d8a645bbbce596e6ceb06786765e34" },
                { "nb-NO", "929aa5f4bf558694213e3f0858b05aef73dd6a8621e3f060ea048ee425d37e28ca1848174ae0bfa75615560486478b79d55ef058f07bd8149de034df3904b41a" },
                { "nl", "ac851ad3162c87af6fed70c4e7bab78f9a092065bcd17a6cb47e30ff3725d7ba6c4669f45b8496f88bf5e71617cfca75cf8d22da0eb5e88a646b2294e47b0b7e" },
                { "pl", "26c6477afcd7eb11fc9c104b0f30bf97e75c127fb1d4a8ac7141e5573967673548853367b8e9694dbc7b50a81ca4e5c9ef2c463cf6af87e86b4a1b3245ba5ed8" },
                { "pt-BR", "4f3d3e6559952b421938cb9121cc0d2767397b858c77250ba332c5b6b42e392425eed5827a968b0abdc03ad9152f64b0a8048ee7e387c69439ecfe831bfb1e50" },
                { "pt-PT", "06e9ece555acc9ccc3d4cbf925f299b2adca36becb7da7a373e938b7f5aa33915a468be3f44b56f5d72dbda46eb7b2dc068cca55053fb8978d336525117c96df" },
                { "ru", "4cbaeb93b7ce54e1efdb895ab0cadb961e4338666310897a5fd2af2c8a10ba9959cb5c56a89d705bfffb26de5329ad6276b18bb3746528bcedd331006ac02dea" },
                { "sk", "f741bb72c199ce5702a6a7282c0f16d50f5b6fc8e630736d206d5aeba53e92d40c8cab753a1a496dd38630056428d57826976ad3851858d2276457d2196a5c92" },
                { "sv-SE", "8a9650af94a029dd6647f4fed336103c26b0aab9a8e834c771b3a6ed28c08468dab0a62be594c4b2361de5f5a34316a1cf7a26b8c2ca36c3d399df3d8d31f7ea" },
                { "zh-CN", "2df73b45b426fe8b6c33afd1aa2e594bc25e10457c97450cd4f79795d74e8c502fa4335ca7815cf570221b383908afddc4368b74c4a0a93f8b1e828108f4d522" },
                { "zh-TW", "f43cba51d1dc556f396c2fbfac7fda1c6bed9b060a5c902014795bed0b48518c4ac4c45b063006092b125bc174d11a2de984c53c870133274163f81fabbfc851" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            // Just go for the 32-bit installers here. We could also use the
            // 64-bit installers, but they have the same languages anyway.
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
            if (!Environment.Is64BitOperatingSystem)
            {
                logger.Warn("SeaMonkey does not provide 32-bit binaries from version 2.53.22 onwards."
                    + "Please consider switching to an 64-bit operating system to get newer SeaMonkey updates.");
            }
            const string knownVersion = "2.53.21";
            return new AvailableSoftware("SeaMonkey (" + languageCode + ")",
                knownVersion,
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^SeaMonkey [0-9]+\\.[0-9]+(\\.[0-9]+(\\.[0-9]+)?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                new InstallInfoExe(
                    "https://archive.seamonkey-project.org/releases/" + knownVersion + "/win32/" + languageCode + "/seamonkey-" + knownVersion + "." + languageCode + ".win32.installer.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    Signature.None,
                    "-ms -ma"),
                new InstallInfoExe(
                    "https://archive.seamonkey-project.org/releases/" + knownVersion + "/win64/" + languageCode + "/seamonkey-" + knownVersion + "." + languageCode + ".win64.installer.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    Signature.None,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["seamonkey", "seamonkey-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return false;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            return knownInfo();
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
        /// Determines whether a separate process must be run before the update.
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
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the SeaMonkey version
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
