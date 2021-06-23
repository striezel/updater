/*>
    This file is part of the updater command line interface.
    Copyright (C) 2021  Dirk Stolle

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

namespace updater.software.openjdk_api
{
    /// <summary>
    /// Contains information about an AdoptOpenJDK release.
    /// </summary>
    internal class Release
    {
        /// <summary>
        /// binaries in the given release
        /// </summary>
        public IList<Binary> binaries { get; set; }


        /// <summary>
        /// name of the release, e. g. "jdk8u292-b10"
        /// </summary>
        public string release_name { get; set; }


        /// <summary>
        /// type of the release, e. g. "ga" for General Availability release
        /// </summary>
        public string release_type { get; set; }


        /// <summary>
        /// version information of the release
        /// </summary>
        public VersionData version_data { get; set; }


        /// <summary>
        /// Creates new, empty instance with all data set to null.
        /// </summary>
        public Release()
        {
            binaries = null;
            release_name = null;
            release_type = null;
            version_data = null;
        }
    } // class
} // namespace
