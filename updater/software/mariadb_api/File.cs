/*
    This file is part of the updater command line interface.
    Copyright (C) 2022, 2025  Dirk Stolle

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

using System.Text.Json.Serialization;

namespace updater.software.mariadb_api
{
    /// <summary>
    /// Represents file information within a MariaDB release.
    /// </summary>
    internal class File
    {
        /// <summary>
        /// Base name of the file download
        /// </summary>
        [JsonPropertyName("file_name")]
        public string FileName { get; set; }

        /// <summary>
        /// type of package, e.g. "ZIP file", "gzipped tar file" or "MSI Package"
        /// </summary>
        [JsonPropertyName("package_type")]
        public string PackageType { get; set; }

        /// <summary>
        /// Generic name of the operating system, e.g. "Linux", "Windows", "Source"
        /// </summary>
        [JsonPropertyName("os")]
        public string OS { get; set; }

        /// <summary>
        /// CPU type for the download, e.g. "x86" or "x86_64"
        /// </summary>
        [JsonPropertyName("cpu")]
        public string CPU { get; set; }

        /// <summary>
        /// checksum data for the file
        /// </summary>
        [JsonPropertyName("checksum")]
        public Checksum Checksum { get; set; }

        /// <summary>
        /// URL for the download
        /// </summary>
        [JsonPropertyName("file_download_url")]
        public string FileDownloadURL { get; set; }
    }
}
