/*
    This file is part of the updater command line interface.
    Copyright (C) 2023  Dirk Stolle

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

namespace updater.software.gitlab_api
{
    /// <summary>
    /// Contains information about a release that was published on GitLab.
    /// </summary>
    internal class Release
    {
        /// <summary>
        /// name of the release, e.g. "118.0-1"
        /// </summary>
        public string name { get; set; }


        /// <summary>
        /// tag of the release (usually identical to name)
        /// </summary>
        public string tag_name { get; set; }


        /// <summary>
        /// Creates new, empty instance with all data set to null.
        /// </summary>
        public Release()
        {
            name = null;
            tag_name = null;
        }
    }
}
