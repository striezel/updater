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

using System.Collections.Generic;

namespace updater_cli.software
{
    public class All
    {
        /// <summary>
        /// gets a list that contains one instance of each class that implements
        /// the ISoftware interface
        /// </summary>
        /// <returns></returns>
        public static List<ISoftware> get()
        {
            var result = new List<ISoftware>();
            result.Add(new KeePass());
            result.Add(new NotepadPlusPlus());
            //Thunderbird
            var languages = Thunderbird.validLanguageCodes();
            foreach (var lang in languages)
            {
                result.Add(new Thunderbird(lang));
            } //foreach
            return result;
        }
    } //class
} //namespace
