/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018  Dirk Stolle

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
using System.Windows.Forms;

namespace moz_checksum_generator
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();
        }

        private void rbFirefoxRelease_CheckedChanged(object sender, EventArgs e)
        {
            rtbBit32.Clear();
            rtbBit64.Clear();
            lblVersion.Text = "";
        }

        private void btnChecksums_Click(object sender, EventArgs e)
        {
            if (rbFirefoxRelease.Checked)
                getFxChecksums();
            else if (rbFirefoxESR.Checked)
                getFxEsrChecksums();
            else if (rbFirefoxAurora.Checked)
                getFxAuroraChecksums();
            else if (rbThunderbird.Checked)
                getTbChecksums();
            else if (rbSeaMonkey.Checked)
                getSmChecksums();
            else
                MessageBox.Show("No product has been selected!", "Hint",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        /// <summary>
        /// generates the code for known checksums from the given data
        /// </summary>
        /// <param name="data">dictionary with data: key = language code, value = checksum</param>
        /// <returns>string containing the C# code</returns>
        string getChecksumCode(SortedDictionary<string, string> data)
        {
            string result = "";
            foreach (var item in data)
            {
                result += "result.Add(\"" + item.Key + "\", \"" + item.Value + "\");" + Environment.NewLine;
            }
            return result;
        }


        /// <summary>
        /// finds checksums for the current Firefox release
        /// </summary>
        void getFxChecksums()
        {
            updater.software.Firefox fx = new updater.software.Firefox("de", false);
            string version = fx.determineNewestVersion();
            if (string.IsNullOrWhiteSpace(version))
            {
                MessageBox.Show("Could not determine current version of Firefox!",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            lblVersion.Text = "Version " + version;

            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + version + "/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                    client.Dispose();
                    return;
                }
                client.Dispose();
            } //using
            //look for line with language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(version) + "\\.exe");
            var data = new SortedDictionary<string, string>();
            MatchCollection matches = reChecksum32Bit.Matches(sha512SumsContent);
            for (int i = 0; i < matches.Count; i++)
            {
                string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + version + ".exe", "");
                data.Add(language, matches[i].Value.Substring(0, 128));
            } //for
            rtbBit32.Text = getChecksumCode(data);

            //look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(version) + "\\.exe");
            data.Clear();
            matches = reChecksum64Bit.Matches(sha512SumsContent);
            for (int i = 0; i < matches.Count; i++)
            {
                string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + version + ".exe", "");
                data.Add(language, matches[i].Value.Substring(0, 128));
            } //for
            rtbBit64.Text = getChecksumCode(data);
        }


        /// <summary>
        /// finds checksums for the current Firefox Developer Edition release
        /// </summary>
        void getFxAuroraChecksums()
        {
            updater.software.FirefoxAurora fx = new updater.software.FirefoxAurora("de", false);
            string version = fx.determineNewestVersion();
            if (string.IsNullOrWhiteSpace(version))
            {
                MessageBox.Show("Could not determine current version of Firefox Developer Edition!",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            lblVersion.Text = "Version " + version;

            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            string url = "https://ftp.mozilla.org/pub/devedition/releases/" + version + "/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Exception occurred while checking for newer version of Firefox Developer Edition: " + ex.Message);
                    client.Dispose();
                    return;
                }
                client.Dispose();
            } //using
            //look for line with language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(version) + "\\.exe");
            var data = new SortedDictionary<string, string>();
            MatchCollection matches = reChecksum32Bit.Matches(sha512SumsContent);
            for (int i = 0; i < matches.Count; i++)
            {
                string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + version + ".exe", "");
                data.Add(language, matches[i].Value.Substring(0, 128));
            } //for
            rtbBit32.Text = getChecksumCode(data);

            //look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(version) + "\\.exe");
            data.Clear();
            matches = reChecksum64Bit.Matches(sha512SumsContent);
            for (int i = 0; i < matches.Count; i++)
            {
                string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + version + ".exe", "");
                data.Add(language, matches[i].Value.Substring(0, 128));
            } //for
            rtbBit64.Text = getChecksumCode(data);
        }


        /// <summary>
        /// finds checksums for the current Firefox ESR release
        /// </summary>
        void getFxEsrChecksums()
        {
            updater.software.FirefoxESR fx = new updater.software.FirefoxESR("de", false);
            string version = fx.determineNewestVersion();
            if (string.IsNullOrWhiteSpace(version))
            {
                MessageBox.Show("Could not determine current version of Firefox ESR!",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            lblVersion.Text = "Version " + version;

            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + version + "esr/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                    client.Dispose();
                    return;
                }
                client.Dispose();
            } //using
            //look for line with language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(version) + "esr\\.exe");
            var data = new SortedDictionary<string, string>();
            MatchCollection matches = reChecksum32Bit.Matches(sha512SumsContent);
            for (int i = 0; i < matches.Count; i++)
            {
                string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + version + "esr.exe", "");
                data.Add(language, matches[i].Value.Substring(0, 128));
            } //for
            rtbBit32.Text = getChecksumCode(data);

            //look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(version) + "esr\\.exe");
            data.Clear();
            matches = reChecksum64Bit.Matches(sha512SumsContent);
            for (int i = 0; i < matches.Count; i++)
            {
                string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + version + "esr.exe", "");
                data.Add(language, matches[i].Value.Substring(0, 128));
            } //for
            rtbBit64.Text = getChecksumCode(data);
        }


        /// <summary>
        /// finds checksums for the current SeaMonkey release
        /// </summary>
        void getSmChecksums()
        {
            updater.software.SeaMonkey sm = new updater.software.SeaMonkey("de", false);
            string version = sm.determineNewestVersion();
            if (string.IsNullOrWhiteSpace(version))
            {
                MessageBox.Show("Could not determine current version of SeaMonkey!",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            lblVersion.Text = "Version " + version;

            /* Checksums are found in a file like
             * https://archive.mozilla.org/pub/seamonkey/releases/2.46/SHA1SUMS
             * Common lines look like
             * bcf9b6828d3143adbfe46066e94650aa67726a02  win32/en-GB/SeaMonkey Setup 2.48.exe"
             */

            string url = "https://archive.mozilla.org/pub/seamonkey/releases/" + version + "/SHA1SUMS";
            string sha1SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha1SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Exception occurred while checking for newer version of SeaMonkey: " + ex.Message);
                    client.Dispose();
                    return;
                }
                client.Dispose();
            } //using
            //look for line with language code and version for 32 bit
            Regex reChecksum = new Regex("[0-9a-f]{40}  win32/[a-z]{2,3}(\\-[A-Z]+)?/SeaMonkey Setup " + Regex.Escape(version) + "\\.exe");
            var data = new SortedDictionary<string, string>();
            MatchCollection matches = reChecksum.Matches(sha1SumsContent);
            for (int i = 0; i < matches.Count; i++)
            {
                string language = matches[i].Value.Substring(48).Replace("/SeaMonkey Setup " + version + ".exe", "");
                data.Add(language, matches[i].Value.Substring(0, 40));
            } //for
            rtbBit32.Text = getChecksumCode(data);

            //look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{40}  win64/[a-z]{2,3}(\\-[A-Z]+)?/SeaMonkey Setup " + Regex.Escape(version) + "\\.exe");
            data.Clear();
            matches = reChecksum64Bit.Matches(sha1SumsContent);
            for (int i = 0; i < matches.Count; i++)
            {
                string language = matches[i].Value.Substring(48).Replace("/SeaMonkey Setup " + version + ".exe", "");
                data.Add(language, matches[i].Value.Substring(0, 40));
            } //for
            rtbBit64.Text = getChecksumCode(data);
        }


        /// <summary>
        /// finds checksums for the current Thunderbird release
        /// </summary>
        void getTbChecksums()
        {
            updater.software.Thunderbird tb = new updater.software.Thunderbird("de", false);
            string version = tb.determineNewestVersion();
            if (string.IsNullOrWhiteSpace(version))
            {
                MessageBox.Show("Could not determine current version of Thunderbird!",
                    "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            lblVersion.Text = "Version " + version;

            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/45.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                    client.Dispose();
                    return;
                }
                client.Dispose();
            } //using
            //look for line with language code and version for 32 bit
            Regex reChecksum = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Thunderbird Setup " + Regex.Escape(version) + "\\.exe");
            var data = new SortedDictionary<string, string>();
            MatchCollection matches = reChecksum.Matches(sha512SumsContent);
            for (int i = 0; i < matches.Count; i++)
            {
                string language = matches[i].Value.Substring(136).Replace("/Thunderbird Setup " + version + ".exe", "");
                data.Add(language, matches[i].Value.Substring(0, 128));
            } //for
            rtbBit32.Text = getChecksumCode(data);

            //look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Thunderbird Setup " + Regex.Escape(version) + "\\.exe");
            data.Clear();
            matches = reChecksum64Bit.Matches(sha512SumsContent);
            for (int i = 0; i < matches.Count; i++)
            {
                string language = matches[i].Value.Substring(136).Replace("/Thunderbird Setup " + version + ".exe", "");
                data.Add(language, matches[i].Value.Substring(0, 128));
            } //for
            rtbBit64.Text = getChecksumCode(data);
        }
    } //class
} //namespace
