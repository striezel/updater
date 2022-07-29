﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);

        
        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.1.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "a0c2f177c98ba5660bdc1553520fd5c63ea48f0f11413249156d2d47ab2941bc8eb729ff116a701681964ec72cbc47842aea81a747825d9c4933139e0aaa0be4" },
                { "ar", "dc9273ea857bc5f3f7ff7b50f19f80db0f2e5e7e80e02eaf268c8f1364a33e1aac9accfd22ae668c5ab532c7641b3f937a08e7944eccc7f5fb61ca0c940d1d7c" },
                { "ast", "7c0cded0b0faaee219833ee7438604c6e1188078162d4327a98dd6104bbcd0153e7704066b2e78c9732cf9c0f01e84d718e0adfa6bce6c6929d1d1f8d0f136f1" },
                { "be", "fcf242a2b2f61d4b708f827338b1cc2d8bc0534a7e45d9b699f5298419a204bf3ff966b06368830289975eb13812b0701da90162cb3f8e6ef1603a82027af9ad" },
                { "bg", "6ccbcb947f822099012ea2906a328835f2a7d8177e04c7abefc660a99c047451f91f42246e37747a2136c2c905f5fec442b1d243553ccf7d549eab459f976121" },
                { "br", "605ce8348aebebc5e8bc374278398d7645dfbf205b4c7e734ac9b92bbe4c978e6d5f431ada0caf9398214462caccf77ec19630c5b4353a879c8c7067b4c974cc" },
                { "ca", "ad4d6547d797924cb16ff79e0737e68da25cccf1f8c1cd87a08c79d3fac2656ff9d3f64ffdc26a190cd2e65cccee71de79f906feed1b07daf42a636af8225d1e" },
                { "cak", "853fd1cbd5436bcc123525a000201843b037ea669fa71e6c7aa516287200d9e8032ddb166dbbfdaf34796abf4c0783862793b7494e63dd790ce6ce2eabb8fa4f" },
                { "cs", "11f793ca3ff4dc8e89bfbe6c41a9c497b8c857a6aab75d8193f0840c76ede3ae1a32a3108c9c765cc1cf0b8a635ad30275e0acd47dcdaedcb9d923eb008717d5" },
                { "cy", "58f710ef69c64f1675c96add2d9d93edb52afa6f58d2382c6589a51b02e709fa827c901682803ed5c91f4b77282fd039bf69510edc1827246b6f5a8227edac6a" },
                { "da", "4162698ff26b139b707af53b2076aec1d99e7e619c15b31ce7b170f44697e65ae9b53fac6af96f72735a3802edf8f788e0aa5e1e4637c598460167703bbe79cf" },
                { "de", "3a1e386af6cb99788ebb16ffdf8516288b4e88157ba8a49e911033771f7de3f0ed1da7b22ddf6c0c88e2e3f1fc01f6cae8032b4dca9440eefaac6f2724bf67cf" },
                { "dsb", "5f4f8621daded6803f6421b91846c713225ce930c7f054ad90267f2b5796eddc106156958c5d3d51a0cb096ca91d45d8cfeefec843b92c1338e02487715cee24" },
                { "el", "1e8d3f687d6b9afbcb67c83a52e0d41f9ad21123ccb17139662eada1fa69f02f3a2a7b0a1447f45f4b4a7c127025137ec5f6cd533bca401b72c035384aac5449" },
                { "en-CA", "21cca7e3682d85672febdc374975b06e52ee1dba1ea2a011c37f0d08863bf3522c0da5951c0ebe14df756aa6e4baecebf4174ce5bd5885d73441e717b64fb4b5" },
                { "en-GB", "7c0e54b6edba42a86f1cf372a43e786387f93911af863509053984dba01069c3aa7e9e3b58aebc597fc671c6271f6ad09886dd822e8aa2e02a06c488ed01ba05" },
                { "en-US", "ac53331001e0db29574d62b73bf167fcac0cfd8579812413e0cfc6439e992adc369fc57604998e80e158f79cabfbe2abca809a33c95db5a72ec1b3e9e969729a" },
                { "es-AR", "4819e40fd879909d0e0f4b427113e55508774303b1f53f15e22c2cd3a46ae3789b0808fd38e4e6951e2c9b1838d727b9696b976d153769d97af3f7bfd449b8ae" },
                { "es-ES", "052c9a790df7d70751ddee6b40aee94c0e8aac114df6931810b7eabc4cbf20fef91593e60751a50adba10077644538c3fa061b8c46508191d91e51b82b2fe262" },
                { "es-MX", "a8e2924ed3aca8936b1e6e4692a2ac919c8e2ee34b9f0d002ac899efa3ed21ec2160ea42df0b76294459f958dcfb54d03d987fc9a5f47879ae2917f21bce8a42" },
                { "et", "5bbe9684c2ce953eca04a01ce46fbbf4d3b857389b39622b570aba86f08cffd9d8b6f4b36a92ca4b659cf820995201517f2bcbe0cbf9dbd702a3f7d5090c1107" },
                { "eu", "564f88c2f1950d094c965d00e4c268c46dda053b8a0d1d5861d0f99054e179f05b030069aaacabfd26b61182be4feae3f7e76eb166ba42f879740c44776e3d5a" },
                { "fi", "8357eaeee63ee61ac33b63dd534ad4c657ce9f828dd6f56cdbd1fc757a826590df25fb479facb7e1ade4c913fc9b857f659d11e89111cf804aac1dbbd1315e7a" },
                { "fr", "67b5384e0c49016d289dbf60b8a9b0795db5bcba2c13d4d261651ef32aa1b9e4a6e1db5feceed60b24e3690a05eed16350a076b7c64baec50949caa2ab7a9520" },
                { "fy-NL", "9abcf62a0b4e0291342cc6574d6fef85438e34a5e1b4479111defd94ae3e00029135820a9f82a6612642dee081d316a40942f61ff9439f44495d3e25a1be5012" },
                { "ga-IE", "388bfeb695010306b2ea0cc7060a339345025287242622c60ced442bf8139f379572d4fc41da78d1db24d6cdd9a55a858b04c39eb8c84781cc2ed52552ef67a7" },
                { "gd", "5aa55758c41e6f1a22fda8d9763edac2aa6dfdc4c6b1b950c94b0a63f4b7328d66fc19b72fd126a4f8c66fbfb5cb24943b2f5659b6fa6833d62b624ca823dc38" },
                { "gl", "cae570bacc6dbcdd091a3a1f6455f2a09633ddc344bf83cbb732ad6b8a48ca15d58a8785ce91f6789b0d9ccdb9e11eae089bda4431e7189d3e0d067d66b316bc" },
                { "he", "e106a231dc5a15f4dd2551f36a324f6a73465a52fa9e81d6473d23608c99d66376c953665622b3ed1d7a843ac161b6e5205333a3d54c72b0f5537807c794f2af" },
                { "hr", "719adfa33273d20a25a01223fb5a425159718ff8ad46e0745d8a6b5f02e4cb9ecc9958acfa4dc82ef2c97b740f1d594e17d4fba2cf2fb12f27f9d40316c82ad1" },
                { "hsb", "1c17833c16c92ed40950481ed7caee53a498b7868d1dbd5a06659dc34a4de8756304187b73e70d419ac396e05e62c09f0ee5130474306bc35e5f669d8451c316" },
                { "hu", "c3c51e55ae77ee2b15098a6c6e55a86c92e7e02335d95861ad1fc2b1de78bbcac9e448fa6ba75b760b115b493ab9935d455831a5ecd36e1c3ab773b3346503d1" },
                { "hy-AM", "d6509f7766f440f0a07e00af491e9d24cde512855b385a18d88f901130d721ec9bf0d452079900dea30bab07c057a321e93bc815b32834a0bd5bd8fa33001fbd" },
                { "id", "aa4efd6eb322c331d5aeadc94e63d9400fd7b40a55d6388dcda3adb38f6c96e29a6d8bb5022f91ec5d56c7fcd14f4d2aa245ccc498a97f9cedab383b745acab4" },
                { "is", "8e094893b9468fa5b2ca9d57f61018e39f4e4dee329002e93a3810434c617e22185ea58afad69a0d5a4c9d5fe7a97c62e2121a078d3ea52df945a709ea444135" },
                { "it", "af91e84e5f87b27412d28e1f4d26b817b3af839755b8bfa902d50da0f23c2661e0be367cddd1712ba24691df2a3b80a588cd3ad211a624ca50066c5ae2fb445c" },
                { "ja", "72f4eebecf2fd1b11d9ed923f72f22867f1e34ddc8fcfa1f42431b5cb318c2a73bebbe9e3c695d5fc5c09cdc2eadbd0fd6dbeb12117eebee4cd4607c22065460" },
                { "ka", "26ddd3d5e3d7a8229a6c81cbe3eb4a0b83438199913db09ff8b2ac1529cbcd8b031e3e3d7f44c6f0e25f9eeb519c15bfa9a51e4e3aa9b50ad770ba6dfdc35705" },
                { "kab", "2eefb72f65233a1f992abaf09aa353fa65f1ec9197ecece5ea42974463bbaab5de7a2636b67e3b38e63ecd4693436f1b873be8c02a9d906d85b02a5506d88245" },
                { "kk", "81c173fa13a21ba8ac5a10d82ffdfc76ca462c1910065cccbf282e42f46731c1d8c452881cdc8dd95606176fcdc3e1ca241fa41025198044cf16bc46dac5cf6a" },
                { "ko", "f911499d9030cc5742fb82540961cd6da62169dd1874acdfd5c1afa7b75fcb1078540aa7d8262abb329b99faf50f3fedebe2ecc44245780db8401abf11e267ce" },
                { "lt", "45b0ed5f2716112253bdba831a02b7f480f953364efe5a2731d212bcf9c08c25077e7407e1c0526a2a93bd28278fa748ce0d2c970e407e386d7cbd0da20a34b6" },
                { "lv", "6c7ce25bed0894a6957158c149a554d5ec4920c20b97fc64408defa14055f9dd6665263f1e62fd583b17f8c112d6f434c3cf1fc6a9bb92b2a23dd47d68479d33" },
                { "ms", "0272ebd14a5c83422114a78f79bdd8e414deec573ccca02cb716751e5d37a9aa4d90d6ae7e5f81124264751d0d47630080687f346a57c9ba7b650a2927f5b1b1" },
                { "nb-NO", "dd64f17d399663176ce5107976deb487e0cdf919d44cec2fc5026f2faae118709e9781fa44afe97fc8b68aa8e5214e4c6c861b796c6d3ae408697cae7fc93017" },
                { "nl", "2ad5d430dbf153c3037e269e9607796d56d2b1dc50453bcdf78d7b999d9035d8a3e0d362a661632187230a0245206e35f631403e5d44d52e0c34df2c0b38df52" },
                { "nn-NO", "75cd52a86d028c53187931d54613f4f91dc01db3abaf95578357cf9eb324304e7b58007277e829ecfa009fd88af176dd3c07be1dfbe15bb295b892f2aab34eaa" },
                { "pa-IN", "381cdf800289602dfc4aeca2792e71658e36ad9a0c93061c84c2ce4dc778e350cb2807cf19433ddc30aa17173765e8eb241cbd1a6e92dbe4d2909ea7a60e14c0" },
                { "pl", "fb2ccfd8531494e6f289f574ff2bf8cbf0e124ae2befce288fff910f3ed0524eb36c1f0b2a4dc071531e29c3f270eaef147878fa3fb35cd8c7b26a55598235c0" },
                { "pt-BR", "bb1cc81a0194061c4c62e284304135c1c57a96b84da61c33ebd7920d56bf58fc850ee0e730691f18f7cdc320384be1601e11d085aea9608328db38131c968582" },
                { "pt-PT", "8c7c1380b4034ed46a130e5c168ad35459e0ed82577faa937119b241aa9bbac2ce2a098d5f941c2501893575ce28a595cc216cb43e5b68e819cb178954daa0a3" },
                { "rm", "da46c457c79a40cc3cead03e5ebd08f7cab83e6c9b9e8c789ca179897813495cffd4cfd3e76c7c6055e69c215a4da126ef835651867f26cb23e5bb0287ad77fe" },
                { "ro", "89ade13a73e7671653c4b9e989edf6132bb9cbbb73def79e8ad2d66adbcd6aea092a82ab06d99357fff51c4e823de14a90e4dac799481cad9329dd9bd6883e32" },
                { "ru", "53b1cd62ace4832d61fafff6bebd7cd07d13c2d87cd3314e8cc39bda5a0e6c4feb09d6de91b428f226f3225cae552fce9910c278341f242da6d703edfbcb3de9" },
                { "sk", "a976af21c7c24a6530d1accc4f6be252eb19248902618350275f8b90af9f1591d03119211da1827627a7d45b3022592339b21d193833ac184a83eca460130722" },
                { "sl", "0160baca9f84828c39a139497e9b7b0515ae6c3426ad02a9288a48dbbd8c77b72f1a6a06dcda66271033f0a6cd48642e1bb70d264754573626abc18cbe8e719f" },
                { "sq", "0920174b5021dba77767d4ed5c3396d686443a05d51c43e6623c14e6b7fc83a14edb0dac8acefac62e95362ffabed0dce0c4908a9e4e6d3bec93a61f8c5eab1c" },
                { "sr", "6de5a8745a5c163bf3dfcee093837de068cf4291e91d15e404bdd09e0891a2e973e422a94f777233ab8a6f4bb245a37d787691de607ad9ef7d50341c9042814c" },
                { "sv-SE", "3f1233f27ff22b236d68fe1bd2b0104cde61dbd1901c32730e6eae9fafdc07927eb293fda6631c8140ce56d72ca059df07a52e40ea653f977e8ec0519e7a95aa" },
                { "th", "e43b91a3c0ddf80ea6d12e12f1f2ea00b0b5dd0f82b5151c32ffd9e2975e22d582c3fecabd12547fe857a92f14652347f794b029e745bbe9487899db3b7fa4e1" },
                { "tr", "e26cfa64d67766db26e15af6127986b042776c344e06c53863cce23478483e7bbc06431c8a2d289d2bff93a87fd748dd08561ae1772714e93d71db0d236f1036" },
                { "uk", "b0224b87f5065a38fdf0c4610dc737b01a72255724c150e57168aab79b8b079e19f907a80c2a09beb6d1406c81d8f4daf77c851a8428c49445bf308733d8506b" },
                { "uz", "2c645a8981aef806ac7d248c05b86da50f3c2384653e90d36a277b0333c7ffecb4a4d5a2432b0d185a022981314a20e242c3279e7c9309437723f0bf3d547446" },
                { "vi", "0755aa69f889f71f8a4a1ac5dcbedf8d6e9bb04f68f7a96ea723c9de4a7b2d1a62c97ba3035249849bd788575e96c2643f40ebd9d097892f7555bf71b482abdf" },
                { "zh-CN", "b162d10454c651d625d8c56a3b9f3c569a7bf173dbfb30af60be6ae20824774baa41d9c805a7d7a53aa063815d7f43c89a64c39b91fda4abab58b1d282b0ce48" },
                { "zh-TW", "85745f363d00128c377dea30fde320f0b820cccd3cc05b6980257ae8139c88a261dce005e8d1b3f8e7da929afd9c3ce62cc637a377573bef7204b90612778d3a" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.1.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "5f6e55f2749e4c0d9cd64bebf66e1c197e42ca4c58539b05d8a7a05d382ab08557c8766f62f76bfb08e61fdc530ad9cf1e15de641bfd96d45bd88b13c0e6619e" },
                { "ar", "f4b1ed27553ac58d2c079a4ce870c96ba4699e10ae9a0af8b095b2016f3b32a02341b537b61b23e76aef430b05cdeb5b137364ac03d2f5e27f13b083902d531f" },
                { "ast", "8ef9441143317ed9900847ef196052f3ae5d15988bc8ad2d20b6a46aafab1b04baf33b0d561368aac731d350bacfc0704767efc1dfa4c8fdcac771b46fdaff0c" },
                { "be", "1cf6bb4fec6a90a7fecb447ec4b820542b3c4e7e24cdd1a0352b41b87f4c094ba48d29fa6beede7de476321704d51fb17a35476f97d74eb1c85e9d38249e7fe3" },
                { "bg", "19e435c57025351ded42c44bb5ffe25dac12cd8c5afc9842ca9d0cf74a1c8e282cd4b70f46da9208ea0e4addd4e63885833123b0d4ed65f242fbe77024048d00" },
                { "br", "460b4b055e5271df09fef1250e1ddca3743ae9df374b3b21d212fccb691dd3ff9e60fcbf2ee1fc3ae533d97c45f937924fcb337933d6d677a3163ebfef7f58c6" },
                { "ca", "d5da2a433d33f642b0ef84f7abcbc2a13edcb97991087d13607dbd30f76318ef813f6d09fe6b1a86f660dde0a777512804a36443e2caa1b5e00186592eeb83bc" },
                { "cak", "da1b73e543f084337c49008253a1aecc195ed74b75bfa99d5bfb44a014ba95feb60cdb2045217bf06285f2942267546fcfea269c0c3e93ee30413bb01cb20b83" },
                { "cs", "a982734046bbff573d819d11bcf0e522a1a8a503490e5af60e530a0a71435f5d2a6ca9af2d80d6ba4c62d52f95374ead26a322a42d92f1b0230f3a747d18700f" },
                { "cy", "b6baa81f615119538dbaeee5ec4e89fe3d381b762f86b5e8c5ba8adffd9437bfc4f7dcf509221830b697b8b8e5ec401e9cf26e35b3b75be066ef1d3ed30d6a73" },
                { "da", "c7ddead0addf2e6d51c5343655a9b95c791dc011be205818fa273dc32229cd19eb3494e5691de5e80a09f50cebc7273c6fe0a2ce3f375ec3c62efc8f7a562963" },
                { "de", "7e4b3edf66723a1ee6dbccfcdabf7477b4cea8e0492c2b7b19418cfbfc5ec69fc712e5702dda6a4289a3ffd068959d4c115553c2fec34f0aec73634ca8f84c2b" },
                { "dsb", "13c5b0c617f9aef672d226f44ea5ccd22848c67bb94d12c21c801fde25cf2e2c3acfd2824ef90d189d0ae8e0d481cb819d90b3b03fc59a8c8d81d1556eb57d30" },
                { "el", "a64556bbc6cd3a1b177968f2a0819045960206afb9a98ac2054ee855ec93255432cd463c936bf936eea0c0a368bf3854ae219407dc6b0cfd6d925daf47f0470a" },
                { "en-CA", "5c53cdbab68008996dfbe588d3e213af6f4f7aab3394016e28b8053b1d48ec0b4e54bcfdd6b28dc0ce0537b4c9fa017a54ded7321c8c7e541847d7d0414e41a8" },
                { "en-GB", "7358fb5e225aaf73d311da0933644c28df0f0cde1dbfa3ed873279bd85795be5ce9a6cf316ed9b153f2b72b44b6d7aee221b458df69d3c19292ce79d63e3d0d9" },
                { "en-US", "d125caf83ed313df855c0112f11e739b8030dbb67f7950ba80de8f20b1e158a7bde0a65776d6b7671194189a1bf7f9b10605e3dd90a5056cd6521c925168714d" },
                { "es-AR", "d18c79975e9f29dcd1e85de1b145e3993b703cacaa4edc9086c629c376b9b445079202e8bf0443b261e18241b635099b6e9272f34af2208e192ae062d9873af6" },
                { "es-ES", "c107f0ae501839ffa0a34eb3a7ef9830ef295b9d8f43eafd4591dc1bd50980f5bb92d9848dd54f81c7b7671a0b6b91e38f351827091fe7ce708964b625d3ace4" },
                { "es-MX", "91328edd804951a58f8db594e109e8a02e86935864d40e7e496ff06100aa8ecccbe094a649ab6aadc47218792e9c60cc78ced4b1afff297fbb56ea6ceb2bac96" },
                { "et", "0833efc503ae5ed1f12f74f98069429e377560e8006928be647bb649422fde80908b663721f09262aea48bf14f7f07206a43c1c8d138a10f1645c373cc24cf35" },
                { "eu", "cfdf85f5fcb07916ae09366562cf8ed511f45db9c960a2d541efa5d5ebcacb8698913ab17422673c3931b8f4f5a7ff5b527edf586958f69f253bb667c8aa911f" },
                { "fi", "afc0a85c9c1c0faf3cf686ccc6e91c357fcd4d51b08ab87be124778794ccb3e3c846cfb97d55162818b2ca6050b59458869ec1882ea1c80d9f5e38653769b87d" },
                { "fr", "599fe36353abdf6aed8c354e749b1ba53460e456671a45fd6eecbeb68815bad833cc1e768acc97b11ad4407e2c516c7d96e9024e6422809a289b9748679013b7" },
                { "fy-NL", "04d39f50fc109e35b5d7cacf1a83f9a5bcf150756e7b4321f3ca0e1ccffc74b55457fc88da7c62a26aae07ba8c43f887492514827796540a0d8a803516ea9b98" },
                { "ga-IE", "c3bb3fa6f6f1aef8f4dd276aac14d144b01407b426ccb0ecde1beafadeddcc3319c32cf5d54406c74db6b9e0c98947a2b7c7a66f5ee62384c53f2cfff3c2932e" },
                { "gd", "11c12e1d4b049cd8d2d7b4e1c48212d0a3200024563f7ca2a8e09da67a46d6685321f3c002bd87e65c90ce79e9f4b83f8583cb90218114dbbfb17055f95a64a7" },
                { "gl", "9a7654c65bd85176c718c02f183ef246435f1ca2250da4a69967c60212b6b02acba438f10a42d5f4a17fed8133e5e42d15efd1f76866cce7e8242febc42d6697" },
                { "he", "24ef6fe343747b8be304761a16d3b33570c4fd3d252b9c61bafe2d135eed8e984d983e36dbd0705bf1e604fcd86d2aba7a3d8bf24bf62817368823473e63beae" },
                { "hr", "2e4e628117311f89414c2f0c7c5d3690853619f245359608aeb3b2348378fc6521f8fadae33819cc5fec50995f143c83a916a77ec72569399ea68ce6e6323bb2" },
                { "hsb", "c9ad4e0c3a528e66d1e8561306e55c7ca396881210f077feedc82456dafd5764f055e708278c7b36f767487aef256d531fb84672ee0167a2a03dca2932ca110e" },
                { "hu", "1ed2ae46d9bed6dd0b844cf9061eee4673752cc3e412bca032c02488af5305d132c0bfef3de94c8efb10d93dfe8ac16af6656d2459d6df2488b85f04781c0067" },
                { "hy-AM", "e6ea72987357d1cb50b185883f503fed06298e14ef7dea4f4f78cd48b5185318b7973098bbddb0da8548fed2a103803e637d06cf66b71289ae6af5b1b989644a" },
                { "id", "e76c48de545de664d20badd847a29f0b90deb01b756060d9a86052334762060533a033fb44ccb632cf2eaf29312a64af2265544d00e18f27c692f87cd9f8a55e" },
                { "is", "bdf97ec220f97a38958de079976b5123ca38dffe4009fdd8b48fcd27a797622fd3c948b96744615680c29e6d38fbec04707ce355aa994c926193f45c5beef5f3" },
                { "it", "034cd5960e705cd652f4b7a072c9bb62c3578a1c692b422ae47472365cfdedd7b90c5ed499dbce3f6af5979544b3630619c235e3568b1406ae1e27999a2cbb9d" },
                { "ja", "307a388a3534d1e3bdd394eee9e054de742181252321b2e2ba42f38a81c140e1c7549307a33f2126e88e38cdaa9724efee44e443d0dd134388ab64e9e68b5f68" },
                { "ka", "150ebf4ed1c232b0d63a10b672145aca5a54dc780a5c7f2aa5d2189b9c7633a6d53888c352dd8104f6ef93d0c724e5ab107d57702898c3251271d24a353138ba" },
                { "kab", "e2daf31e367df8bb721066875c7fded387ce19c2e0430cb3657e88005182bd01cbf12160566ef27bd855eb4d64583ab1e5b913594e5dc861b0c16412379b126e" },
                { "kk", "8ef3427e843f714d99fb21e6efcc0d70ec60ee97b7690ab4124069105c341987f77bf2eaa013ff2ae010633a7b6f3262bd7b313702c9be4fc915425439f95fbe" },
                { "ko", "f389b74aeac2506ed658585a350f7625d53875414c9a4c3cd050a7f696ca7c661fd747908f7f3370113b977b2ecaa12cd3659224272735324555c0e7e0d754ed" },
                { "lt", "3ca063c5d91edbc95d758c9a0a9037b6c5b2ddf05dc94e73eb0f5cadf53c3570ed77aef9af679e53982e3c27e7c15b4e5c36a3b4f2cc1d0a585a5e69132dd228" },
                { "lv", "4c2484ec7ec6a657c7ecdb472f9a640827952f4f41666d3a7bd0c6882094935369f5f1941f608170da859e36d884acf05e7bc8c7c523ccbcbd141a46af9a2c41" },
                { "ms", "2e7c35af8883a6007c58c8113ec1957eec28d60dd310ec1767d21ed9925eca81d0a032d0aad080ebb2d4c62bb37936b9968f3f06d2c05a7871d716e8ee2a0773" },
                { "nb-NO", "3e2ac2d738f8db023a3d54849dfdb042bf6d364bd5dc6c83be55862498c857fe98dddff8b812ba0ee45d0781765f196cb299f4af34cf324cc8c1c23137e865c3" },
                { "nl", "8cd9398792bc74546d08d1fc0fd26b7d88f5e3dbe85d4be5df41fdd1a0b6dceb0a9cafb109cb3f9a61086bf9afb4cc832b8e3a303ba956f16142a9c3d813dd39" },
                { "nn-NO", "323a8fe93ef15995f2d285668bb3c908a17cce6a422e12bfe9db85c84544261787acf8c20e1bc85fecb10828b566b9ddc94179117690905f27bc95625b3e3629" },
                { "pa-IN", "34d649dca51499fe70a7fbe4fdcdd073e124c6c110c0e4bb386a2b4917861cc7c9bb373db7731f6d78e38564f98436de6d167434d24d1ab7371dcef50089fab3" },
                { "pl", "89ce1d95a37c393547e7e825d2b00e7452ac54d743337e3020a909efd60880f9ef8a17aea2f30607b45b073df2afdb4a2c75c7432b79afeb3e4efdf37983cf42" },
                { "pt-BR", "9eae4f90a2f20f4c75500dc181da8ae7581ee9863cf9a2fad10d1a3a82209a790eeecc964cd97ba721feb9f7bfe242bc662bf401d8a0324d92e0c9497651efbd" },
                { "pt-PT", "26bc13ae2e21010ae17814221eb140722ffb1735a638b48893ada6dd83157d7be1f28579b465bf7427b2b0c62af1f21c5436cbc0c9ea0f9588eccc0078e76cdd" },
                { "rm", "7bf954b93feffed3a3e07494c25cf97d6aa878e8f1719ecc33ca826789aeb13c876245e12a5c2e65029ada0a7c8ca4e7a6c6cd9ec9afde7de27ae317cc0858db" },
                { "ro", "1baed98ee88292a510fda54248058fd38270ff87568e8efefd1235262d54911f87b114fe7408879cd76a4c1d190c17145cb93d40150ce3813886518a76f7d17e" },
                { "ru", "aa11d4156e92e1348a129f95e5428f86882492d23eecf05d834b68e7ae6f0f58f3119728dcfd96d8e710c47862b384bb5b270c0e18cdb7783b391cd00718fec7" },
                { "sk", "fc75381484e77ec3d32b2e7e92f70a0a1cda4a8b3d1e458a29ca725396996817bd6edcf149c4e78f5c82e106ee45c6b34d524882f0de9d10e64280cab52532c9" },
                { "sl", "37911c07cbe090891c25d63b8c65c139e3cf9cf3d64f4556b4519c7fa53b07a18b0246c0bb424908b9ab10c48721481eb067785092b7530951d5f6f35d2a51df" },
                { "sq", "76742838c609e067b30cd05f1584e7366f78404d87caf091458a102d4a2ed8d76bffe6ec2c33b208205cfbb67b86e947d23e29777f5defed7ca14f88bd14009e" },
                { "sr", "e6582c6414c94d41951354a554bb4031ce60ca5571df424d0e887127c5aa566b8d5007a880759804f80031fdb922a9b29a5e557699ea937e90b0071cf1b1d6f7" },
                { "sv-SE", "9d2f3cfeb916ddc01496f2ae1b6a1d36a6e8c112348b16a4ed6a8ca91b2acdb981a099277fe0e3ccfc4fcc33881e8625765aee3c85070337d1a95397a0dfa779" },
                { "th", "eb66765a9e92945e6853ca7746d5fc2e40defc977a64e0ff8b1f7baa600448c1f9bfe5ba0753989b91b516a850bb9d5329357e01cb8977f55dbfe7639062e458" },
                { "tr", "299511a18e2a004f2e5096a362e6073673152d1e7a186a6f68eacddda0254f334f7de15e4302eb11f30cac9cc3c2a1986e95aa4aafb592d5f0b0fd0e90d54411" },
                { "uk", "a1e56df4a6baeb2cb5f1276cd41b13a9f3fb76947ae47be29dbb22a90495bcfdee378fdd263a1601f414f983415d86cbbfcfbc40ca46589ec33cc6dc4c4f727f" },
                { "uz", "ffb07369e310855809570b9c825115ec2e4ce45c53525b3b5edd2fbda70dea29828f7ed38169e4e959fae28aaa9ba1e9687fef37386c6282f972f62ccbf54db6" },
                { "vi", "e94761ccb453993404da263c5dc96f7827f9db6c5fa2b995ce7dd04dbb73d53b226f5ad5cc8288c9d1496e686757e6abf13271a0b80a22f33310faef7dae7ffb" },
                { "zh-CN", "d6138b60e78f6264e796b3d300443595f19c9d5aea1c72e9483b52bdbed4442a9a651204b5974875275b201f85b2f20160016edce3e283620b20f3f6fad908d0" },
                { "zh-TW", "838c21f100258da3856a82fdab404ff61999553eb61838790bd9025b08e599bd46ce00e3c9599b414975c885a35748d5c9d3474b91b21c609f1009478d645599" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            const string version = "102.1.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32 bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64 bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent = null;
            using (var client = new HttpClient())
            {
                try
                {
                    var task = client.GetStringAsync(url);
                    task.Wait();
                    sha512SumsContent = task.Result;
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value.Substring(0, 128),
                matchChecksum64Bit.Value.Substring(0, 128)
            };
        }


        /// <summary>
        /// Indicates whether or not the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>(1)
            {
                "thunderbird"
            };
        }


        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
