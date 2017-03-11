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
    /// enumeration to indicate the hash algorithm that is used for checksum calculations
    /// </summary>
    public enum HashAlgorithm
    {
        /// <summary>
        /// unknown or no hash algorithm
        /// </summary>
        Unknown,

        /// <summary>
        /// Message Digest 5, 128 bits
        /// (This algoritm is weak and practically broken. But some vendors use
        ///  it as the only checksum for their setups/installers.)
        /// </summary>
        MD5,
        
        /// <summary>
        /// secure hash algorithm 1, 160 bits
        /// </summary>
        SHA1,

        /// <summary>
        /// secure hash algorithm 2, 256 bits
        /// </summary>
        SHA256,

        /// <summary>
        /// secure hash algorithm 2, 384 bits
        /// </summary>
        SHA384,

        /// <summary>
        /// secure hash algorithm 2, 512 bits
        /// </summary>
        SHA512
    } //enum
} //namespace
