/*
    This file is part of the updater command line interface.
    Copyright (C) 2022  Dirk Stolle

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

using updater.data;

namespace updater.software
{
    public class MariaDB_10_5: MariaDB_Base
    {
        /// <summary>
        /// Default constructor.
        /// </summary>
        /// <param name="autoGetNewer">whether to automatically get newer
        /// information about the software when calling the info() method</param>
        public MariaDB_10_5(bool autoGetNewer)
            : base(autoGetNewer, "10.5")
        { }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("MariaDB Server 10.5",
                "10.5.16",
                null, // no 32 bit installer
                "^MariaDB 10\\.5 \\(x64\\)$",
                null, // no 32 bit installer
                new InstallInfoMsi(
                    "https://downloads.mariadb.org/rest-api/mariadb/10.5.16/mariadb-10.5.16-winx64.msi",
                    HashAlgorithm.SHA256,
                    "535e398cb2e0ee34cc7dfebcc241afb5632bc1ca3d99f2be3cf8b184274f9339",
                    signature,
                    "/qn /norestart")
                );
        }
    }
}
