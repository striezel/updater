﻿/*
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
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Handles updates for VLC media player.
    /// </summary>
    public class VLC : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for VLC class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(VLC).FullName);


        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public VLC(bool autoGetNewer)
            : base(autoGetNewer)
        { }


        /// <summary>
        /// publisher of signed binaries
        /// </summary>
        private const string publisherX509 = "CN=VideoLAN, O=VideoLAN, L=Paris, C=FR";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 8, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            const string version = "3.0.21";
            return new AvailableSoftware("VLC media player",
                version,
                "^VLC media player$",
                "^VLC media player$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://get.videolan.org/vlc/" + version + "/win32/vlc-" + version + "-win32.exe",
                    HashAlgorithm.SHA256,
                    "4bd03202b6633f9611b3fc8757880a9b2b38c7c0c40ed6bcbefec71c0099d493",
                    signature,
                    "/S"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://get.videolan.org/vlc/" + version + "/win64/vlc-" + version + "-win64.exe",
                    HashAlgorithm.SHA256,
                    "9742689a50e96ddc04d80ceff046b28da2beefd617be18166f8c5e715ec60c59",
                    signature,
                    "/S")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["vlc"];
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
        /// Determines the last version of VLC media player, which is usually
        /// the latest version, too.
        /// </summary>
        /// <returns>Returns a version number, if successful.
        /// Returns null, if an error occurred.</returns>
        private static string getLastVersion()
        {
            string htmlCode;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://get.videolan.org/vlc/last/");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for latest version of VLC: " + ex.Message);
                return null;
            }

            var reTarXz = new Regex("vlc\\-[0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?\\.tar\\.xz");
            Match matchTarXz = reTarXz.Match(htmlCode);
            if (!matchTarXz.Success)
                return null;
            // extract new version number
            string newVersion = matchTarXz.Value.Replace("vlc-", "").Replace(".tar.xz", "");
            return newVersion;
        }


        /// <summary>
        /// Gets the latest available version from download site directory listing.
        /// </summary>
        /// <returns>Returns latest available version number, if successful.
        /// Returns null, if an error occurred.</returns>
        private static string getLatestAvailableVersion()
        {
            // See https://get.videolan.org/vlc/ for available versions.
            string htmlCode;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync("https://get.videolan.org/vlc/");
                task.Wait();
                htmlCode = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for available versions of VLC: " + ex.Message);
                return null;
            }

            var reVersion = new Regex("\"[0-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?/\"");
            var matches = reVersion.Matches(htmlCode);
            var latestVersion = new Quartet("0.0.0.0");
            string latestVersionString = null;
            foreach (Match m in matches)
            {
                if (!m.Success)
                    continue;
                var possibleVersionString = m.Value.Replace("\"", "").Replace("/", "");
                var possibleVersion = new Quartet(possibleVersionString);
                if (string.IsNullOrWhiteSpace(latestVersionString) || possibleVersion > latestVersion)
                {
                    latestVersion = possibleVersion;
                    latestVersionString = possibleVersionString;
                }
            } // foreach
            return latestVersionString;
        }

        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searching for newer version of VLC media player...");
            // get new version number
            string lastVersionString = getLastVersion();
            if (null == lastVersionString)
                return null;
            var lastVersion = new ShrinkingQuartet(lastVersionString);
            string availableVersionString = getLatestAvailableVersion();
            if (null == availableVersionString)
                return null;
            var availableVersion = new ShrinkingQuartet(availableVersionString);
            var newVersion = new ShrinkingQuartet()
            {
                major = lastVersion.major,
                minor = lastVersion.minor,
                patch = lastVersion.patch,
                build = lastVersion.build
            };
            if (lastVersion < availableVersion)
                newVersion = availableVersion;
            // should not be lesser than known newest version
            if (newVersion < new ShrinkingQuartet(knownInfo().newestVersion))
                return null;
            // version number should match usual scheme, e.g. 5.x.y, where x and y are digits
            var version = new Regex("^[1-9]+\\.[0-9]+\\.[0-9]+(\\.[0-9]+)?$");
            if (!version.IsMatch(newVersion.full()))
                return null;

            // There are extra files for hashes:
            // https://get.videolan.org/vlc/last/win32/vlc-2.2.4-win32.exe.sha256 for 32-bit
            // and https://get.videolan.org/vlc/last/win64/vlc-2.2.4-win64.exe.sha256 for 64-bit.
            var newHashes = new List<string>();
            foreach (var bits in new string[] { "32", "64" })
            {
                string htmlCode = null;
                using (var client = new HttpClient())
                {
                    try
                    {
                        string full_version = newVersion.full();
                        var task = client.GetStringAsync("https://get.videolan.org/vlc/" + full_version + "/win" + bits + "/vlc-" + full_version + "-win" + bits + ".exe.sha256");
                        task.Wait();
                        htmlCode = task.Result;
                    }
                    catch (Exception firstEx)
                    {
                        logger.Warn("Exception occurred while checking for newer version of VLC: " + firstEx.Message);
                        // Some mirrors have invalid certificates or no certificate, and that will
                        // cause the request to fail.
                        // Try again with another mirror that hopefully has a valid TLS certificate.
                        // The get.videolan.org/vlc/... URL redirects randomly to a VLC mirror server.
                        // Some of those servers might not have a valid TLS certificate, so we try
                        // some other mirror.
                        try
                        {
                            logger.Info("Trying another VLC mirror instead...");
                            string full_version = newVersion.full();
                            var task = client.GetStringAsync("https://ftp.halifax.rwth-aachen.de/videolan/vlc/" + full_version + "/win" + bits + "/vlc-" + full_version + "-win" + bits + ".exe.sha256");
                            task.Wait();
                            htmlCode = task.Result;
                        }
                        catch (Exception ex)
                        {
                            logger.Warn("Exception occurred while checking for newer version of VLC on a mirror: " + ex.Message);
                            return null;
                        }
                    }
                    client.Dispose();
                } // using

                // extract hash
                var reHash = new Regex("^[0-9a-f]{64} [\\* ]vlc\\-" + Regex.Escape(newVersion.full()) + "\\-win" + bits + ".exe");
                Match matchHash = reHash.Match(htmlCode);
                if (!matchHash.Success)
                    return null;
                string newHash = matchHash.Value[..64].Trim();
                newHashes.Add(newHash);
            } // foreach

            // construct new version information
            var newInfo = knownInfo();
            // replace version number - both as newest version and in URL for download
            string oldVersion = newInfo.newestVersion;
            newInfo.newestVersion = newVersion.full();
            newInfo.install32Bit.downloadUrl = newInfo.install32Bit.downloadUrl.Replace(oldVersion, newVersion.full());
            newInfo.install32Bit.checksum = newHashes[0];
            newInfo.install64Bit.downloadUrl = newInfo.install64Bit.downloadUrl.Replace(oldVersion, newVersion.full());
            newInfo.install64Bit.checksum = newHashes[1];
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
            return [];
        }
    } // class
} // namespace
