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
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Handles updates of Mumble VoIP client.
    /// </summary>
    public class Mumble : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Mumble class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Mumble).FullName);


        /// <summary>
        /// default constructor
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Mumble(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher name for signed binaries
        /// </summary>
        private const string publisherX509 = "CN=SignPath Foundation, O=SignPath Foundation, L=Lewes, S=Delaware, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 7, 12, 13, 14, 18, DateTimeKind.Utc);


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mumble Client",
                "1.4.287",
                "^(Mumble [0-9]\\.[0-9]+\\.[0-9]+|Mumble \\(client\\))$",
                "^(Mumble [0-9]\\.[0-9]+\\.[0-9]+|Mumble \\(client\\))$",
                new InstallInfoMsi(
                    "https://github.com/mumble-voip/mumble/releases/download/v1.4.287/mumble_client-1.4.287.x86.msi",
                    HashAlgorithm.SHA256,
                    "e1e020e12bb8cc55176b0cbeed6d7abfbe8a138eb69418360ac159a3b46c0262",
                    signature,
                    "/qn /norestart"),
                // 64 bit MSI installer started with 1.3.0.
                new InstallInfoMsi(
                    "https://github.com/mumble-voip/mumble/releases/download/v1.4.287/mumble_client-1.4.287.x64.msi",
                    HashAlgorithm.SHA256,
                    "bbd8d57fd450c98e08553518c523a07ddadf3cff503f70db561f4b53fdb1c292",
                    signature,
                    "/qn /norestart")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "mumble" };
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
            logger.Info("Searching for newer version of Mumble...");
            var request = new HttpRequestMessage(HttpMethod.Head, "https://github.com/mumble-voip/mumble/releases/latest");
            var nonRedirectingHandler = new HttpClientHandler
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(nonRedirectingHandler);
            string currentVersion;
            try
            {
                var response = client.Send(request);
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location.ToString();
                client.Dispose();
                client = null;
                request = null;
                response = null;
                var reVersion = new Regex("tag/v[0-9]+\\.[0-9]+\\.[0-9]+$");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                currentVersion = matchVersion.Value.Substring(5);
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Mumble version: " + ex.Message);
                return null;
            }
            // Use known info, if version has not changed.
            var known = knownInfo();
            if (currentVersion == known.newestVersion)
                return known;

            /* New URL is something like 
               https://github.com/mumble-voip/mumble/releases/download/1.2.19/mumble-1.2.19.msi
               and signature file is something like
               https://github.com/mumble-voip/mumble/releases/download/1.2.19/mumble-1.2.19.msi.sig
               However, the updater cannot check signatures yet.
            */
            
            // construct new version information
            var newInfo = known;
            // replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = currentVersion;
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, currentVersion);
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, currentVersion);
            // no checksums are provided, only signature files
            newInfo.install32Bit.checksum = null;
            newInfo.install32Bit.algorithm = HashAlgorithm.Unknown;
            newInfo.install64Bit.checksum = null;
            newInfo.install64Bit.algorithm = HashAlgorithm.Unknown;
            // Fall back to known old signature data.
            newInfo.install32Bit.signature = new Signature(publisherX509, certificateExpiration);
            newInfo.install64Bit.signature = newInfo.install32Bit.signature;
            return newInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Technically, mumble.exe is a blocker, but the installer just closes it,
            // if it is running.
            return new List<string>();
        }

        /// <summary>
        /// Checks whether the update needs to unistall the old installed version first.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if the software needs an uninstall before the upgrade.</returns>
        private bool needsFreshInstallation(DetectedSoftware detected)
        {
            // Update path from 1.3.x to 1.4.x is broken, so anything before 1.4.0 needs
            // a clean installation, i. e. uninstallation before installation of a new
            // version. See <https://github.com/mumble-voip/mumble/issues/5076> for more
            // background information on that.
            var detectedVersion = new versions.Triple(detected.displayVersion);
            var v1_4_0 = new versions.Triple("1.4.0");
            return detectedVersion < v1_4_0;
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
            return needsFreshInstallation(detected);
        }


        /// <summary>
        /// Returns a list of processes that must be run before the update.
        /// This may return an empty list, if no processes need to be run
        /// before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (!needsFreshInstallation(detected))
                return null;

            var guid = GetGuid(detected);
            if (string.IsNullOrEmpty(guid))
            {
                logger.Warn("Warning: Updating from Mumble versions older than "
                    + "version 1.2.3 to version 1.4.230 or newer is not supported."
                    + "Please uninstall your old Mumble version manually and then "
                    + "download and install the current version from https://www.mumble.info/.");
                return null;
            }

            var processes = new List<Process>(1);
            var proc = new Process();
            proc.StartInfo.FileName = "msiexec.exe";
            proc.StartInfo.Arguments = "/qn /x" + guid;
            processes.Add(proc);
            return processes;
        }

        /// <summary>
        /// Gets the GUID product code of the detected version.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns the GUID of the MSI installer, if it is known.
        /// Returns null otherwise.</returns>
        private static string GetGuid(DetectedSoftware detected)
        {
            var guids = new Dictionary<string, Dictionary<ApplicationType, string>>(22)
            {
                { "1.3.4",
                    new Dictionary<ApplicationType, string>(2)
                    {
                        { ApplicationType.Bit32, "{A6C30898-08C3-443B-8B38-CCB7C1987227}" },
                        { ApplicationType.Bit64, "{E6A3B3D0-4009-4E04-B9A2-A3CB34446E01}" }
                    }
                },
                { "1.3.3",
                    new Dictionary<ApplicationType, string>(2)
                    {
                        { ApplicationType.Bit32, "{6438D3B9-051D-46DE-8A05-179DCB0D54E3}" },
                        { ApplicationType.Bit64, "{6EBE8FBF-D1D3-42E6-BB02-E5D351961C8A}" }
                    }
                },
                { "1.3.2",
                    new Dictionary<ApplicationType, string>(2)
                    {
                        { ApplicationType.Bit32, "{C5E7BFF3-8982-4757-AE3B-AA669DB96EB8}" },
                        { ApplicationType.Bit64, "{05E8CCAF-C7A6-4EFF-8F41-A086463EBD11}" }
                    }
                },
                { "1.3.1",
                    new Dictionary<ApplicationType, string>(2)
                    {
                        { ApplicationType.Bit32, "{DE5D7A84-5329-4661-A2F8-A8057D35D3C3}" },
                        { ApplicationType.Bit64, "{CBBDE4D7-7447-41A2-9192-DAD6EF36A54D}" }
                    }
                },
                { "1.3.0",
                    new Dictionary<ApplicationType, string>(2)
                    {
                        { ApplicationType.Bit32, "{1DE423A7-5929-4C32-B953-7A7607A6E352}" },
                        { ApplicationType.Bit64, "{6011D53E-52D0-49DC-B40F-1C9579523D29}" }
                    }
                },
                // Versions before 1.3.0 were only available as 32 bit builds.
                { "1.2.19",
                    new Dictionary<ApplicationType, string>(1)
                    {
                        { ApplicationType.Bit32, "{4D99DEC0-BDEE-4E79-8ED0-2905081FF30A}" }
                    }
                },
                { "1.2.18",
                    new Dictionary<ApplicationType, string>(1)
                    {
                        { ApplicationType.Bit32, "{41970536-610A-4EB4-845B-D150A74CAAC7}" }
                    }
                },
                { "1.2.17",
                    new Dictionary<ApplicationType, string>(1)
                    {
                        { ApplicationType.Bit32, "{8A01C920-26AD-4574-8C2B-95D9245B1EBE}" }
                    }
                },
                { "1.2.16",
                    new Dictionary<ApplicationType, string>(1)
                    {
                        { ApplicationType.Bit32, "{E938AC6B-A1EB-40C7-8FFE-D4A325C1EA5D}" }
                    }
                },
                { "1.2.15",
                    new Dictionary<ApplicationType, string>(1)
                    {
                        { ApplicationType.Bit32, "{3320748F-375E-4A80-BD48-EC42124FB502}" }
                    }
                },
                { "1.2.14",
                    new Dictionary<ApplicationType, string>(1)
                    {
                        { ApplicationType.Bit32, "{79D15E9E-B707-45AD-A078-F2E941C85456}" }
                    }
                },
                { "1.2.13",
                    new Dictionary<ApplicationType, string>(1)
                    {
                        { ApplicationType.Bit32, "{101B046E-2AB7-4758-B887-86F47270519D}" }
                    }
                },
                { "1.2.12",
                    new Dictionary<ApplicationType, string>(1)
                    {
                        { ApplicationType.Bit32, "{DF623011-5402-4ECC-9F00-B46A41BF8EAB}" }
                    }
                },
                { "1.2.11",
                    new Dictionary<ApplicationType, string>(1)
                    {
                        { ApplicationType.Bit32, "{2C0B4F07-7DD2-4D69-9A97-77AE3A37280F}" }
                    }
                },
                { "1.2.10",
                    new Dictionary<ApplicationType, string>(1)
                    {
                        { ApplicationType.Bit32, "{2A8C1469-B7F5-4EE2-95E1-316895A211A7}" }
                    }
                },
                { "1.2.9",
                    new Dictionary<ApplicationType, string>(1)
                    {
                        { ApplicationType.Bit32, "{60236C77-018F-4536-8544-ACE0B4314BDF}" }
                    }
                },
                { "1.2.8",
                    new Dictionary<ApplicationType, string>(1)
                    {
                        { ApplicationType.Bit32, "{1BC144A3-20EF-49DD-8EBB-E421E128E30F}" }
                    }
                },
                { "1.2.7",
                    new Dictionary<ApplicationType, string>(1)
                    {
                        { ApplicationType.Bit32, "{FEFBBD52-B304-4D81-9DF8-E19C1373AC30}" }
                    }
                },
                { "1.2.6",
                    new Dictionary<ApplicationType, string>(1)
                    {
                        { ApplicationType.Bit32, "{1C21B645-FED0-4E08-AA65-A7B388F10083}" }
                    }
                },
                { "1.2.5",
                    new Dictionary<ApplicationType, string>(1)
                    {
                        { ApplicationType.Bit32, "{871F39A1-1671-4161-A012-1D4820346A69}" }
                    }
                },
                { "1.2.4",
                    new Dictionary<ApplicationType, string>(1)
                    {
                        { ApplicationType.Bit32, "{AF348C2E-7596-481B-92E0-B211836AB949}" }
                    }
                },
                { "1.2.3",
                    new Dictionary<ApplicationType, string>(1)
                    {
                        { ApplicationType.Bit32, "{C3E9887A-23BA-4777-8080-191A5AFCAB74}" }
                    }
                }
                // Mumble 1.2.3 seems to be the first version with MSI installer.
                // Older versions use an .exe installer, but we do not handle that here.
                // Mumble 1.2.3 was released in 2011, so this is enough to cover more
                // than ten years of old releases.
            };

            if (!guids.ContainsKey(detected.displayVersion))
                return null;
            if (!guids[detected.displayVersion].ContainsKey(detected.appType))
                return null;
            // Entry with GUID exists, so return it.
            return guids[detected.displayVersion][detected.appType];
        }


        /// <summary>
        /// Determines whether the detected software is older than the newest known software.
        /// </summary>
        /// <param name="detected">the corresponding detected software</param>
        /// <returns>Returns true, if the detected software version is older
        /// than the newest software version, thus needing an update.
        /// Returns false, if no update is necessary.</returns>
        public override bool needsUpdate(DetectedSoftware detected)
        {
            var verDetected = new versions.Triple(detected.displayVersion);
            var verNewest = new versions.Triple(info().newestVersion);
            return verNewest.CompareTo(verDetected) > 0;
        }
    } // class
} // namespace
