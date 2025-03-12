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

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace updater.software.mariadb_api
{
    /// <summary>
    /// Contains data about a MariaDB release.
    /// </summary>
    internal class Release
    {
        /// <summary>
        /// ID of the release, usually the version number, e.g. "10.5.16"
        /// </summary>
        [JsonPropertyName("release_id")]
        public string ReleaseId { get; set; }

        /// <summary>
        /// Name of the release, e.g. "MariaDB Server 10.5.16"
        /// </summary>
        [JsonPropertyName("release_name")]
        public string ReleaseName { get; set; }

        /// <summary>
        /// Release date as string, e.g. "2022-05-21"
        /// </summary>
        [JsonPropertyName("date_of_release")]
        public string DateOfRelease { get; set; }

        /// <summary>
        /// files for the given release
        /// </summary>
        [JsonPropertyName("files")]
        public List<File> Files { get; set; }
    }
}
