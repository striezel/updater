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
    /// enumeration to indicate whether 32 bit or 64 bit application was detected
    /// </summary>
    public enum ApplicationType
    {
        /// <summary>
        /// application type is unknown
        /// </summary>
        Unknown,

        /// <summary>
        /// 32 bit application
        /// </summary>
        Bit32,

        /// <summary>
        /// 64 bit application
        /// </summary>
        Bit64
    } //enum
} //namespace
