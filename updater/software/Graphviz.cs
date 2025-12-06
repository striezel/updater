/*
    This file is part of the updater command line interface.
    Copyright (C) 2024, 2025  Dirk Stolle

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
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using updater.data;
using updater.software.gitlab_api;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Handles updates for Graphviz.
    /// </summary>
    public class Graphviz : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Graphviz class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Graphviz).FullName);


        /// <summary>
        /// Constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Graphviz(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            return new AvailableSoftware("Graphviz",
                "14.1.0",
                "^Graphviz$",
                "^Graphviz$",
                new InstallInfoExe(
                    "https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/14.1.0/windows_10_cmake_Release_graphviz-install-14.1.0-win32.exe",
                    HashAlgorithm.SHA256,
                    "0e6088e80eaaca5a3d32bfb7636abc117cfd14b6aab529e0c89f9f2b9b6b4a1e",
                    Signature.None,
                    "/S"),
                new InstallInfoExe(
                    "https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/14.1.0/windows_10_cmake_Release_graphviz-install-14.1.0-win64.exe",
                    HashAlgorithm.SHA256,
                    "0fd4add0ac2f5048eea33ef2a66750c91a39c80645fdd555b58acec0fa264ff2",
                    Signature.None,
                    "/S")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["graphviz"];
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
        /// Tries to find the newest version number of Graphviz.
        /// </summary>
        /// <returns>Returns a Triple containing the newest version number on success.
        /// Returns 0.0.0, if an error occurred.</returns>
        private static Triple determineNewestRelease()
        {
            string url = "https://gitlab.com/api/v4/projects/4207231/releases/";
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
                var task = client.GetStringAsync(url);
                task.Wait();
                var response = task.Result;
                var releases = JsonSerializer.Deserialize<IList<Release>>(response);
                if (releases != null && releases.Count > 0)
                {
                    return new Triple(releases[0].Name);
                }

                return new Triple();
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Graphviz version: " + ex.Message);
                return new Triple();
            }
        }

        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searching for newer version of Graphviz...");
            var newerVersion = determineNewestRelease();
            var known = knownInfo();
            var knownVersion = new Triple(known.newestVersion);
            if (knownVersion > newerVersion)
                return known;

            // Checksums are available under URLs like
            // https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/12.1.1/windows_10_cmake_Release_graphviz-install-12.1.1-win64.exe.sha256
            // and https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/12.1.1/windows_10_cmake_Release_graphviz-install-12.1.1-win32.exe.sha256.
            var client = HttpClientProvider.Provide();
            string full_version = newerVersion.full();
            string response;
            try
            {
                var task = client.GetStringAsync("https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/" + full_version + "/windows_10_cmake_Release_graphviz-install-" + full_version + "-win32.exe.sha256");
                task.Wait();
                response = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Graphviz version: " + ex.Message);
                return null;
            }

            // Find checksums.
            // The 32-bit installer checksum is listed in a line like
            // "9b25d9790d178882dd4aa1e23f501decacc75d7f1bdb88d608806e5144506780  Packages/windows/10/cmake/Release/graphviz-install-12.1.1-win32.exe".
            var regEx = new Regex("[0-9a-f]{64}  .+" + Regex.Escape(full_version) + "\\-win32\\.exe");
            Match match = regEx.Match(response);
            if (!match.Success)
                return null;
            known.install32Bit.checksum = match.Value[..64];
            known.install32Bit.downloadUrl = known.install32Bit.downloadUrl.Replace(known.newestVersion, full_version);

            try
            {
                var task = client.GetStringAsync("https://gitlab.com/api/v4/projects/4207231/packages/generic/graphviz-releases/" + full_version + "/windows_10_cmake_Release_graphviz-install-" + full_version + "-win64.exe.sha256");
                task.Wait();
                response = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Graphviz version: " + ex.Message);
                return null;
            }

            // The 64-bit installer checksum is listed in a line like
            // "07d452119318c4516fab56714df1f81972b0f7e5e08815a67e6af384df39c62e  Packages/windows/10/cmake/Release/graphviz-install-12.1.1-win64.exe"
            regEx = new Regex("[0-9a-f]{64}  .+" + Regex.Escape(full_version) + "\\-win64\\.exe");
            match = regEx.Match(response);
            if (!match.Success)
                return null;
            known.install64Bit.checksum = match.Value[..64];
            known.install64Bit.downloadUrl = known.install64Bit.downloadUrl.Replace(known.newestVersion, full_version);

            known.newestVersion = full_version;
            return known;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return
            [
                "dot",
                "dot2gxl",
                "gml2gv",
                "graphml2gv",
                "gv2gml",
                "gv2gxl",
                "gvcolor",
                "gvgen",
                "gvmap",
                "gvpack",
                "gvpr",
                "gxl2dot",
                "gxl2gv",
                "mm2gv"
            ];
        }


        /// <summary>
        /// Checks whether the software is in the list of detected software.
        /// </summary>
        /// <param name="detected">list of detected software on the system</param>
        /// <param name="autoGetNew">whether to automatically get new software information</param>
        /// <param name="result">query result where software will be added, if it is in the detection list</param>
        public override void detectionQuery(List<DetectedSoftware> detected, bool autoGetNew, List<QueryEntry> result)
        {
            // Note: This is basically the same functionality as in the class
            // Improved64BitDetectionSoftware, but adjusted for Graphviz which
            // does not provide an installation directory via registry, so the
            // uninstall string (path to Uninstall.exe of Graphviz) is used
            // instead.
            // Furthermore, the executable to check is not directly beneath the
            // installation directory but one level further down inside the
            // "bin" directory.

            // 32-bit systems use normal detection.
            if (!Environment.Is64BitOperatingSystem)
            {
                base.detectionQuery(detected, autoGetNew, result);
                return;
            }
            // 64-bit systems might need adjustments.
            var resultBase = new List<QueryEntry>();
            base.detectionQuery(detected, autoGetNew, resultBase);
            foreach (var item in resultBase)
            {
                if (string.IsNullOrWhiteSpace(item.detected.uninstallString))
                    continue;
                // Remove enclosing quotes.
                if (item.detected.uninstallString.StartsWith('\"') && item.detected.uninstallString.EndsWith('\"'))
                {
                    item.detected.uninstallString = item.detected.uninstallString[1..^1];
                }
                string installPath = System.IO.Path.GetDirectoryName(item.detected.uninstallString);
                // See if we need to adjust the type for the 64-bit variant.
                string exePath = System.IO.Path.Combine(installPath, "bin", "dot.exe");
                utility.PEFormat format = utility.PortableExecutable.determineFormat(exePath);
                if ((format == utility.PEFormat.PE64) && (item.type != ApplicationType.Bit64))
                {
                    item.type = ApplicationType.Bit64;
                    item.detected.appType = ApplicationType.Bit64;
                }
            }
            result.AddRange(resultBase);
        }
    } // class
} // namespace
