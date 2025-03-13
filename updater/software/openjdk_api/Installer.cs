/*
    This file is part of the updater command line interface.
    Copyright (C) 2021, 2025  Dirk Stolle

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

namespace updater.software.openjdk_api
{
    /// <summary>
    /// Contains installer information for an OpenJDK installer.
    /// </summary>
    internal class Installer
    {
        /// <summary>
        /// SHA-256 checksum of the installer
        /// </summary>
        [JsonPropertyName("checksum")]
        public string Checksum { get; set; } = null;


        /// <summary>
        /// download link for the installer
        /// </summary>
        [JsonPropertyName("link")]
        public string Link { get; set; } = null;
    }
}
