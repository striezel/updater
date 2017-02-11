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

using updater_cli.data;
using System;

namespace updater_cli.software
{
    public class KeePass : ISoftware
    {
        /// <summary>
        /// gets the currently known information about the software
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public AvailableSoftware info()
        {
            return new AvailableSoftware("KeePass", "2.35",
                "KeePass Password Safe [2-9]\\.[0-9]{2}", null,
                new InstallInfo(
                    "https://kent.dl.sourceforge.net/project/keepass/KeePass%202.x/2.35/KeePass-2.35-Setup.exe",
                    HashAlgorithm.SHA256,
                    "6274E8CB 0358EF3E 3906A910 36BC8413 8A8FDE60 6A6E926B 9A580C79 F9CFC489",
                    "/VERYSILENT",
                    "C:\\Program Files\\KeePass Password Safe 2",
                    "C:\\Program Files (x86)\\KeePass Password Safe 2"),
                //There is no 64 bit installer yet.
                null);
        }


        /// <summary>
        /// whether or not the method searchForNewer() is implemented
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public bool implementsSearchForNewer()
        {
            return false;
        }


        /// <summary>
        /// looks for newer versions of the software than the currently known version
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public AvailableSoftware searchForNewer()
        {
            throw new NotImplementedException();
        }

    } //class
} //namespace
