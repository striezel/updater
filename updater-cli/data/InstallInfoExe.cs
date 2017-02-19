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

namespace updater_cli.data
{
    /// <summary>
    /// holds information about an .exe installer
    /// </summary>
    public class InstallInfoExe : InstallInfo
    {
        /// <summary>
        /// default constructor
        /// </summary>
        public InstallInfoExe()
            : base()
        {
            //base class constructor does initialization
        }


        /// <summary>
        /// constructor with initial value parameters
        /// </summary>
        /// <param name="_downloadUrl">URL where the installer can be downloaded</param>
        /// <param name="_algo">hash algorithm that was used to create or verify the checksum</param>
        /// <param name="_check">checksum for the installer - hexadecimal representation</param>
        /// <param name="_silent">switches for silent installation</param>
        /// <param name="_def32">default installation path on 32 bit systems</param>
        /// <param name="_def64">default installation path on 64 bit systems</param>
        public InstallInfoExe(string _downloadUrl, HashAlgorithm _algo, string _check, string _silent, string _def32, string _def64)
            : base(_downloadUrl, _algo, _check, _silent, _def32, _def64)
        {
            //base class constructor does initialization
        }


        /// <summary>
        /// whether the installer is a simple exe file, not using msiexec
        /// </summary>
        /// <returns>Returns true, if the installer does not use msiexec.</returns>
        public override bool isExe()
        {
            return true;
        }


        /// <summary>
        /// whether the installer uses msiexec
        /// </summary>
        /// <returns>Returns true, if the installer uses msiexec.</returns>
        public override bool isMsi()
        {
            return false;
        }
    } //class
} //namespace
