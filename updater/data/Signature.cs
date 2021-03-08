/*
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

using System;

namespace updater.data
{
    /// <summary>
    /// Holds information about a signed binary file.
    /// </summary>
    public struct Signature
    {
        /// <summary>
        /// An instance that contains no signature information.
        /// </summary>
        public static readonly Signature None = new Signature(null, DateTime.MinValue);


        /// <summary>
        /// Wrapper method to create a signature that does not expire.
        /// </summary>
        /// <param name="pub">distinguished name of the publisher (certificate subject)</param>
        /// <returns>Returns a signature with expiration date way ahead in the future.</returns>
        public static Signature NeverExpires(string pub)
        {
            return new Signature(pub, DateTime.MaxValue);
        }


        /// <summary>
        /// Creates a new Signature information record with given publisher and expiration date.
        /// </summary>
        /// <param name="_publisher">distinguished name of the publisher (certificate subject)</param>
        /// <param name="expiration">expiration date of the certificate</param>
        public Signature(string _publisher, DateTime expiration)
        {
            publisher = _publisher;
            expiresAt = expiration;
        }


        /// <summary>
        /// Checks whether the structure contains data that can be used for verification.
        /// </summary>
        /// <returns>Returns true, if the structure contains useable data.</returns>
        public bool containsData()
        {
            return !string.IsNullOrWhiteSpace(publisher) && expiresAt > DateTime.MinValue;
        }


        /// <summary>
        /// Checks whether the signature has expired.
        /// </summary>
        /// <returns>Returns true, if the signature has expired.
        /// Returns false otherwise.</returns>
        public bool hasExpired()
        {
            return expiresAt.ToUniversalTime() < DateTime.UtcNow;
        }


        /// <summary>
        /// distinguished name of the publisher (certificate subject)
        /// </summary>
        public readonly string publisher;


        /// <summary>
        /// expiration date of the certificate
        /// </summary>
        /// <remarks>The expiration date is not required to be the same as the
        /// actual expiration date in the signature, it just usually happens to
        /// be the same. This is just a hint after what date the signature information
        /// shall not be used by the updater anymore.</remarks>
        public readonly DateTime expiresAt;
    }
} // namespace
