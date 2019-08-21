/*
    This file is part of the updater command line interface.
    Copyright (C) 2017  Dirk Stolle

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

namespace updater
{
    /// <summary>
    /// Provides access to some Git information for the updater.
    /// </summary>
    public class GitInfo
    {
        /// <summary>
        /// Gets the name of the Git branch.
        /// </summary>
        /// <returns>Returns a string that contains the git branch.</returns>
        public static string getBranch()
        {
            return Properties.Resources.branch.Trim();
        }


        /// <summary>
        /// Gets the hexadecimal SHA1 hash of the current commit (40 hex digits).
        /// </summary>
        /// <returns>Returns the SHA1 hash of the current commit.</returns>
        public static string getCommit()
        {
            return Properties.Resources.hash.Trim();
        }


        /// <summary>
        /// Gets the date of the last commit (e.g. "2017-01-29 14:59:33 +0200").
        /// </summary>
        /// <returns>Returns the date of the last commit.</returns>
        public static string getCommitDate()
        {
            return Properties.Resources.date.Trim();
        }


        /// <summary>
        /// Gets a Git-like description (e.g. "v2017.04.18-5-gabcdef") of the current commit.
        /// </summary>
        /// <returns>Returns a Git-like description (e.g. "v2017.04.18-5-gabcdef").</returns>
        public static string getDescription()
        {
            return Properties.Resources.description.Trim();
        }


        /// <summary>
        /// Gets the a short version of the hexadecimal SHA1 hash of the current commit (less than 40 hex digits).
        /// </summary>
        /// <returns>Returns a short version of the SHA1 hash of the current commit.</returns>
        public static string getShortHash()
        {
            return Properties.Resources.hash_short.Trim();
        }
    } // class
} // namespace
