/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

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
using System.Linq;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Developer Edition (i.e. aurora channel)
    /// </summary>
    public class FirefoxAurora : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxAurora class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "120.0b5";

        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxAurora(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = knownChecksums32Bit()[langCode];
            checksum64Bit = knownChecksums64Bit()[langCode];
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/120.0b5/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "da121f6228048104ddde7781473483022e19b946a7b27ab2cf887eeabcf026071b404d1e89c11d8f08abd07aaf919d6c9442e5ec982b791edb33ec7d9a2f4d56" },
                { "af", "21be195609b2534ab68e779f2b0d2cfd7270fa9513a50967b6e63e249f71d5bf5a238564d5c87a430864e973f3038f4a1d06cd546c8b5373ec3fba411ffd79fc" },
                { "an", "bc64b507d9b9611340c00f39473c5191c9bb4cd8d47fce38777ecba7aaf29d00d0997efcaccdbf510543fa2326b1912e6e335225920edbb71600ccfc06aa1304" },
                { "ar", "9fab7fbd1904a83b42dbd316e8ba489b21a8a3e42167553f22bd75cb048069bdbc7027c080795174a8257b0fac770f7de610f2b91748633ad47f5bdd407746eb" },
                { "ast", "be418304cb489b085f7472faf882774e32fc6ef59607e053eb32cb46cd0508e211d1ea87340e3e45fb832b81401ae4817deb427418c4d8820a17ff4d220b14cb" },
                { "az", "0e4b849bf6481416e191d64ca3e9950556c433dfd9e9d1dcd3a266b286c06485978df48deff745b306602ecaa10f6984911e448e0e87f2fc625c78323e6c5cc3" },
                { "be", "e84cca27e6abc29d0bf3eedb788f4f7b32e53f02a1c96b8dfed1f696e69eaad91c05d18960d8c9c877ab68b1ac323f96af2370c5fdaa78bd2ddaef90c57a81a7" },
                { "bg", "c003c58916bcdec5aa61b2d114b0be8d7876e1ea55b317b7b329c6cfdc0e753ba7ad5eca25db34e3b5eab7b82e4a898f46517b9c6774f9130605093ea5f8a92b" },
                { "bn", "d1fe98a00b61a6f5f915e8e0da364047204e3ae39da1f24246e224b9a1564c7af45d167742715247943683f5c15e400117edee70fb6bf222be6bdf7dd16fe76e" },
                { "br", "8f46d54a8823a9b6cf45c7acf08ad10fd543a01513edcb3698a5f08187410eaf0c4a18fab1354ffb67959510b53bb32c54d961640a187b28a5c664e792af33e6" },
                { "bs", "968031ae71133bc2ca200e3441e2c0a56545da3bd6032881b9693e942261c784ed5586cdc941d1c263195b4c42e4557c5d6025d75e3c2d6f134b2ae1c80e8ca1" },
                { "ca", "1f4a8e5c29e59e65ff121ddd6cb62683b85ffd819d7a3c6507097667e68bf5a7990b4d04bdf68ff9afe8fbd3127cf0437614db9ae914c7f9c34fc1a2e3d07aff" },
                { "cak", "dc7a1e900ad4747a07c827bc01e33b08f60353046777148742567c0802a6147ddfb3844b27e4160b5b6abb543565d1eb1aa78dee71dff7e451b86863312cf3be" },
                { "cs", "2c948c428fcbabc4b241f9ea96d1666a9dcf3374b1943eebb84b64c309ec0c6f148e42e2ae9bfcd66057fe506829802b7a3c28cf888c37544daade7c6744f0f0" },
                { "cy", "48ea85eb957b86eb0f5e3a5b6de704cdd0e50d58fc7dfe725282ac03184d28817927b124eac0e6abfde885ca6a0b51f69efad802242024021979e8295c251d43" },
                { "da", "d8493d3d6a08631b7e94a4e120cd3086364e8a8adc64b64a57f34cb91271308180cb904cd0afe1c4b4611ecd97b21e88b3521639bf01882105d692ee0adb29e7" },
                { "de", "e0a269564a30412def8708884373a063f014f50bc1d16a5e63887256362fd3eada59493b3a20fa39ec25afcb909455deb644980f08b59df22b5b8c7afc5c815b" },
                { "dsb", "e33378d015a47b5e6f5d11faedb447bf2d5ce486369e6db9a0bbfcacbfda639aa24f5f07c6fcdaec92badd579685d1739eadcbe7c14a0fcd94a36a282363d7aa" },
                { "el", "d63996c772c0f2074f31ebaceb7ffdac9f3151b08dd8a9d7c34e97a0be704ec31e4ba5038aa6812fc4cf97acd778932826e4761476c687e646f7526cd961d1a9" },
                { "en-CA", "3e5ce899951aaf55d8dd881d5ec6e5a66f47480efc6926c3e53ba096798f31a9a657f7ef6080a0931e82ab5f30505d0d956e21521bb4d3766b745417e75d4c4d" },
                { "en-GB", "d38b6f1783a948deb2d9221dbd80a5d927b950b46b8437dc7efa5b1a21bcd4f013651f0c2a3cef254d96f9a3697472d904e6ebd21e0ce5f6d000db35b42c0cf1" },
                { "en-US", "3129b8a2463f0639299e702a67fa9281e9df67e3a6d6691a8f7fc87b71d406c5efde14bb2dba58d5f1dc26f5dfd1ba3a61e7e24242b9311e64935768c454397b" },
                { "eo", "c7bbc4ae72a3709bd2e0a2c869fd6b486b70d3ec368afb27466ed550357e9f7f99c44b381653bb2cd4b34d20b911f23e69d4e13e8da637331a440d24aafa6b9b" },
                { "es-AR", "970b0829afdd7ed392412000952f3b05d7ebe7a415d105f9de062120c5f7d99b7780a55c1bd330002501e32007cec048e7a0c0fca92da76fb4dbe38a51bb9f70" },
                { "es-CL", "c5c745316e8d49fe0055e8c4faf1d4b8e6c067e99e35a56edca74f83b73bf833bdf64b7260f0f7beb7d67c3ded1c7f214aa88a1e1ba85de5e9c0b26a875b60dd" },
                { "es-ES", "e078400331a5be4e175a3bd067ae98d05898e880b5c80e02ff8d0d1b666d60bc77a60743e75d3944e590f56cdee25e9f525f2e15aea01607e44ba952cd36cdff" },
                { "es-MX", "efffd9e8139ea605378c601805a89adbbe0dfcd115bf12fdd14c9ac448d9fcadccbf290a0c7636648935806c591165b29253c5d18187837a2e1186da8ca5b39c" },
                { "et", "f15f6f7c17921249aecf1e0c16f5b7a1c08cd1fc0b473a6d06c1c579d36594bcd83040b36274238743fbf2d48799c46477fc2970b71b5bc928755c63bf32de84" },
                { "eu", "52dd31014be4677a82c34ddf5fd0c08d6d7fbebb9478609fc00b87073e4fba05b80b7bdbf481f55d51854af38a5134a308e53dfa3f8d2efbf9ba842d05fcb7d9" },
                { "fa", "72b73e47548e8af39f2c1ff7c33acdb821087dad1d095e6248b12e4f21d099f4ce43d260b664eaed48b1c60bb5eb582fa2b60fd4430be3c69794e355ae864602" },
                { "ff", "3a9d3d7886231b7b8f04c623bca939c30d10bfffe42018eadf359a67029a9124c4fe2a1818e7a28776ba2c859ed5bf6d93cc2c93ccebae168e9303be65c68a5b" },
                { "fi", "8801e82e7e2040acfd6e51a52831e049e0645fd5bd05721f2d0c9f13ad3fd39b8ed124a9cdb298d4c7075809cf1e93c0e2c69e041c012d3b7191e8ed49ff4e7a" },
                { "fr", "005014b3f700f0fd7bd947c7f24cf27a50f045795395733603326ba98598f401c56ec5a061442d7dbf1fef710295e6bb19029210f279bf6bbc7bc517f19c30e4" },
                { "fur", "661713d3cc80afaaa5c608bcbe6e4f7a97f5db06f772cfce14a05245c6779edd89badc389e533cfe4467dfae2a61b68b97c647c27643b2e10034ac298f1b4699" },
                { "fy-NL", "e2abe86b5c31023169c020b2acadb66b8ac855a7614da9b03872d56b5bee7ad81b1f5f9b2eb073e14df813f94dda9819c427e82ed0437159947b38b1e1c67171" },
                { "ga-IE", "63a885889aa3116d9293c6fa3995ba4eaeeeea3a427f1f34d31cc7246f4aeeb37a09f4ea70aa821a2df0ef76f0e88ab82cb983a53b9dfe48c27e950a01cd11e8" },
                { "gd", "39dd35c84c19ba61e32d89d7f8098c17a33a2b1473e10a5053e8b4267f9d6631cf33aeba19a7d7eda2042a9b8640ef8971147885da4eff489df16d8b1786f84a" },
                { "gl", "a0d398c1749e5b0ada8561daa0d6ef6b95cbfdee89eb01e8ddaecbe0214b91cf514957df155de07b68503b1efb433d98cc1b7a4332a45ae1d2104fe6216c8401" },
                { "gn", "bf2f3d22dfd2c576f4ce2d7d9cd4d4089a0be2416a44145c568499905fb2478398aaa34c9c95f5a5c3b9ef021b4e99f685cc189d0d1bd12bd7c449e30c669f61" },
                { "gu-IN", "3f56e8f099106c7aae943412e3d7f1b76c0235a84cba57835bad71121c9babf116743f251f58eef6438a14f67dd1fb622e0ce31f3f89bb99ef994f3fb41e0648" },
                { "he", "2015c996c7396027abca1d5f753f1eb10bbd4ee59346c151d5cf860dcc12ef6a0af95f70bf8fe86c161f404da046055e461f495efdc87677d615b261ab0efcfc" },
                { "hi-IN", "8faac510601db8337dbff71d51003c315bf71e8e4ff5d498ccad6fd4e1192ab80c9230d847710150bd342ab468a2229782ff7576b6a726a3ce3ccaed0cdbc9ba" },
                { "hr", "ce04ccde8420016313668e8a0aa985da30985c46909f4762747a9e3f80c09006b990b345352acfd9396e0816d1f32af88a853b5d5180814e35cb8a363a668856" },
                { "hsb", "e3faaa8d0109875b62b4399499f23b7b64bcb51d589a1c857ce1e1068f5045f2046695962e9c4d61bdd3e948f11cebc051c9baf5b3be904190e4b22284ddd5e8" },
                { "hu", "b41ebbb896b28dfd3f55b2257c7c906f984088cb8a3d6a3c1545f5e7dd3d7599a308fe02b712cdfe505a6cdbd5fc8acb47538983db7e00ac95c159f19fb88d8e" },
                { "hy-AM", "61300fa810a2fa0aedfbd3875094c107047fd01a0de0d2d238f12944113b45be42e50683864ad32e2e263f3da65a6bd0b317b82f1307c0d2a4d2e54518892540" },
                { "ia", "c871821bd4fc6a29a6533060c79a060ecccd106759f3b066f52f31e19059f9b3e3410243f8bda8d8768aa9e0351105f36ce6de9e2ac32523bfc60b0fa9b15c18" },
                { "id", "0350cd06c2d04fffd02a07037809dd9ea7d3430499ffd8b98c75ec09dc7d86122dcffc4d36fe8933e20c3db363118a7d4c09629350a9f65786b25ad9354571b2" },
                { "is", "057b878702f8e7d59cde4ad07c2a03850e297e0c1f091acf9187dbd34f36e64649bbf28d0ad26048a16fcc3dce209f710a10c29ce00320fc6beeb7975abf8b87" },
                { "it", "1cfc203f4df42a5e73beead2312bc7aa360307d9f8adcf215e12e9fdf0a894e28c7cf319eabeb85e980370ce88dee1eea0e193969a1d872858b7683629c8452c" },
                { "ja", "b9b2a21aabd4b9571cdccf9158a35bd9d72ddab1fe0d500ff525fb165d981e26837e8e52ccec94306a642bcc8313edc28b001b78a4bcf7e803b52c5d2cd9b104" },
                { "ka", "c3f36034786856b8dc68ecfdbc18e924bf68decf4ff93a648d62decf1591e25162f54ebe58074db268c58de640c3a4dcf3631d8facfa3e1cd0436c392eedbac6" },
                { "kab", "a17ffddf9efd7ee68f00272aa003c9cec162f02fc57be7a619100e11d428317671315d73ed02c6b53eda00355e56cb99fc221a720ff2cb4a7d31cceac985fc3f" },
                { "kk", "05608f5acd722b36de1527a07b116798799e468246d497516c8e142ef9575a321b688d8e74726432913f85af66c6910b3d774889751ddc390caeab142e89e112" },
                { "km", "0992ca9b82e10e1b12c26a0e1a82640d86d7c68bc6f88d3908a297e18c2a7ea951786eeee92d9162c95fbe219c785fc655f26326d94c31ea1e0d701c74681cb2" },
                { "kn", "dbdc408a7549358020362ca361e54c91ed3b911e6c020efbd915da9c5e5877c758afcba360599fff9d6dcb8ec675d97626a00c1da386f43a8febf49b7f9bb5f9" },
                { "ko", "39276f8f769cda6d742f09b27ffddafd2bd3cb8273b90ae0f385be0df4b680ad4c3407eb45527e0d2fb8a8c09b67f837d3357dd3fcd2de54b79bdc439fb7c835" },
                { "lij", "c1a62fc8920d2b7ffa28e56cd4fa5f454ebd9f9746279fa0b55450470293cf7680ed777316464d9ea279c2d750e1124e0636b053311fc4ee765400f39008c045" },
                { "lt", "e93485e35d8840f1e724b9579bf40106f42ad4943818c9647a1231ee1c51a7e3dbbee005d66fa0a16f0b24c22909edaaf4c2eb748dd59f1f5b284029e1e0acc5" },
                { "lv", "0003562343381d4b70d102dadcc5b0c47c98a94391c41b86b63a64baa65c32e5cd9bd41e29978b6edb5603eeb345658bd4932a4e0610df588529ae1024326e3e" },
                { "mk", "15775dfe7be4c52187ab73038877b22df3585d53e43576e32b6dd49cbea098a6e266d341b15f2c7841edfb712bbcb2bc697d41acafba560efef50a83d4f0d51d" },
                { "mr", "79070759175d98aa6adb0643a575e2827cc83621476bd7486cb65183cc0da5e9875e0b9c9c46636ef720c6c7a4c68aff0ac4616fb09bcab712ca28b58d4afcc6" },
                { "ms", "53d52a1b1ba18b57da8cc675c07ab43fee0cfb114121f478521f75c58ba6704a54f361410568bc21b007f38ee1aa81e517a4446abeef7a63e262fe71705d63a5" },
                { "my", "33c58a9566f9ab0e8bdb3f9c43b685505245b750b9b04adcc7d71c80e8763d269312a132e18b1f2e4a080dc187c781f0c533bb30e82080a2ef0071feec94c4c5" },
                { "nb-NO", "e704e610052bc66ce2a168f3af045d7b8c4d0889de985e67a533685e0abde2c7767e3c553d3e4d06e64a9f6cee94917a93dcc65eb626cdfc33fec121eb9dbfbc" },
                { "ne-NP", "d0a78ee967061b5b1653f0c7ba34f3c906ebb43393c3e122a3a33e0db2b9278442e1d24ee21c1c041ab7b4875db546f8494e837c26e96ec6c8d2faeff8d6ee9b" },
                { "nl", "baf78c7eecb6eb56e1a1fde42fae5e5b0b04e155cecd268c36c99589f5e89a13adf33362f26018fc0756e2dfebc6c3aeac4eecde211a57de5658dcfc8f60a0f3" },
                { "nn-NO", "1efe9187c7bbd77ea0a6d98d26918edc0bf3f7a349a77adb03d08ea901ef85777e96119a58063ee64c38935a3f5fa3bb84e27a4a631dc9527341a81a47dbb569" },
                { "oc", "b578c6a77aeaa02a4f6b658e2a3685c5249397dc5ae120e9cdc7835f1a998b76176f4973a2dbf0451c03af962860de7eaad6962a20a02592390d05bdc92dcb9f" },
                { "pa-IN", "40102f927efc93436c66c3cd7383098748c11d957e489936ab1121db4f84eff8e14a9b4a63da5883420e51444c55e01b4800bc3032f4180f7825c3a73bf6cd60" },
                { "pl", "5c039ead384991b5e2800b3b0ebc5f31986b567f7784e76f69e3cb1833285deeb944298d0b710e74053c5b8c9b7bd1b112cf47f14ebf97de5bfc5b9ec2d650ec" },
                { "pt-BR", "df8731c8f6e2a5591042d53cd83560cafc3c2d8243a22eb68b986b697490c103c6782e5e9d98ab39859737a21f46143b16b401d5d9821fcde576b839c6b156ac" },
                { "pt-PT", "1cdebb523c45206b7ac86a3054879a2bc7a9b9c709ea80fa90eb9363ec3053a83bade1ff5488d7183c3ab817d076c6a1df22c0ebf3ae805c640b20c5d268fcc5" },
                { "rm", "120f609105f3eac83ba0c7b99a7fb18fd6d8618cc07f76b5cad780bd41338407ba489b0c8b793cd9dbe53e33b7aea393ee8477caf8f0ebc8c21f147c1eb3664f" },
                { "ro", "cb651423688ae43815a6e3775a0245ee85847b57718f3983cc016d4095b102d08d70d3694f4c994fd3ee3c41c49f696fd8017164eb3c67cf37df825a7d9bc1b5" },
                { "ru", "291496177455c1a434472fd2363dad8b0ab50047a5d1cbdd4c279b4718f8c49d2951ab47d39a5a5bbec5bf5ef82a69324e719e1f5d5787f8758afdd8f099e81b" },
                { "sat", "b55f982fc8fd8e3257e73b0bafa16cbf52864c3bf5e1572f8573d75c9201668142fde1a2efe9bde54cda623dacd991489cec04c6c115365ad2aa3e1635f8b540" },
                { "sc", "57c534915be280f45d1b9d437842f2e2b0f3e1985819e996beb27aeb78427be844ce5a4c8a495094c1a3d6197c299a8e0f7fb60d3cc0d0ee767ab70001c745ab" },
                { "sco", "3882e7d34e691e9368d0e960c61849765969e0d42596ac7e4ca79c37519e384e43f72be7a22a5d40e7f07461041d759b3c1ff4bb0c3d0dbb30a1b3c819e53e28" },
                { "si", "29e2abfab49d5c8f44c370e8fbee1e3a1841780eda37cea6f7a881b8c29007123e35d015b951a81e119f11d57205326e80d8a5169ab80049395edac5aad55f1b" },
                { "sk", "6656ffb90386ed98aeaecdb363bca2f240b583bd450e0b82cc5f5f269d5e7a9b876e83dc6ede17adb7461eecd639e07639f89b0044215ae97511c1294f928bf6" },
                { "sl", "7c0c7565becef039e5836e04918e3a00d99f660e16c35c073fc4431b8f1f3dacc08a166011218aaa11e46f6413fcd27cbdf43ed28aa45e6548335b803819a237" },
                { "son", "3a24f1b8b7d7a7d242a2147c007467d3ad08955b18cb5a7deddfeafd552a7a9b48a9c1a143355221e4bc8bf7f4370784a6e37f7323c471a375e46b8f39c46bd7" },
                { "sq", "276c3c872fc35c91671723a49ab8c4311b8843d385ecbe953f9e61c412a1abfa035b09d1a39356ca4b479133c659bf2b545d9750f9b0a25ec34dbe5cc5640f1b" },
                { "sr", "1e3da64af34a9b383d0cd0466e8ae921151f7d7ef156f7347f72c2397d97fbe94e16f968290b74ef717c45d84cd9cdbae76eaf7d834cc13637ff1bf621051043" },
                { "sv-SE", "f1291ff62441aa4b86b49401495f6104edd5fcbf955828367f35c83f7cd1c01667f888712fa74f61bc8cbe7b1f8a2fdcaef34221f0a52dbc5bd4c3d100e4fdbc" },
                { "szl", "947de02374c1143a1785bdf3586f56036ff1f2b0acc3e011d82353fac159c8fa21d3b7f3a3e4f38dab1dc861771ec7bb653775a545f35e25574b52ef6fd09cb6" },
                { "ta", "a76268237ac42e903c3994aaa24ae1d30d3368a138ffefdaa6a34662324b949da0827522ebe6f2a7b94a334534e79c0a4b2324761407887c388cd0baa4068a83" },
                { "te", "3b404c7569fb6a6dc135f1beefe37564ab833f708e707d373cc454f0910d2e9b69bbc169e64ab36bdf816cb674bf7a4bb17ed4a0e7e3eeee7bd20c9b3a1443a2" },
                { "tg", "37c99000a5fea1e699a015cb5523ce2aa9b3baf8d6b2a8ea7073c41e322066d23f1b2209e30569af52bdb39d05b3342262647f854b41db6462cd5c4abdaa8453" },
                { "th", "4e4b5220b4be32b4b13eccc29fd42dcd775fb18f00a60783b52aa0e2a26f1bb93a9b01f40e8b594131f1e55efcde3ac25466789e40b7179b802d1a08de233602" },
                { "tl", "cee9d040ce7b1f7a2437125364af89befef406739874eb2dbf2c744b307ef5148a668690aef6daf48dca51e5bb0227ca173a2c8cdaf4df6d33cb5d0ce7c2524c" },
                { "tr", "976b99e96b6e3604fa9c21bb74f66679bfc61eee1f3576ecb2111013d8910d9a2db5adf19eb09e8262f086f8a6d98e4ebabe1ad7d35d385e9aaab1c50dc592a7" },
                { "trs", "a73873368bef8235367f1e53ed9f83240596513aff73130479b3894654bf99408b7806069f1e6667c573a24057e11a90e38d9cf9dcee1c8a5ef0d55d64542b8c" },
                { "uk", "976d00e344555d0bc4be73e75ba8559c1767965ecfcf42bba17677811b4f400c2ff3999c29e4fd0f3349af8491df12dfb6693c14a371294f1ce450efadd1cd57" },
                { "ur", "0812942e7344d8364e410ab35cb92916e83ed8495d977476dfe37956fe3ba09d09a0106727a0ec25fdd4e77a3686ee54bb758f19d8efbe50065aef1140617ec2" },
                { "uz", "7cffbb58383833c3782c40a2b9ac8eba570583ea9ced8ff007175e34dcb69d79dea21fda2674ac33b9c2dc057067958840f4fad16e8d5d5d5338da774551e275" },
                { "vi", "43dc807a7da64f5ccd22ec47f733c8aa15bbafd10ce81fc15f49340c5524d22c28e015e146748ba4bb6a211ce64ba939824faae517c9a7d1516b87061a56dbfc" },
                { "xh", "fe2cd3e014728265a196c21777b41dee0ab3b06d9369eea0c8f4f8b10c45bfb77a270fddf1bc84e482ec77b7d9f33ad7ffed15bd78b187d2b3987b4e9357b41b" },
                { "zh-CN", "3f3c5b6d903f5292f8243132067fe848a418451119e21d274a60b15f94fc9bcb4ea48f56dcb7dfe31d9b5b916fcb830e089b496b54487d6c4a7430f494611a41" },
                { "zh-TW", "6bcc321bcad228ab064fc8910b00c4150f78d05b0657a564addab61a737d23d90f6dfd964a4b0aa2c38be093ec4ea68afaa08c0ce94336b21b893ec81a02b870" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/120.0b5/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "e822d337d4f22dc528d345307f350eb68e602d84a1f25c99a4be344f70a8fe31ac30be7fd5a403cdfbf88d7df8a09d85dfe8eef5577ffa6486a4a4ac4dbe8b2c" },
                { "af", "8bde8da05f66041df63a28e30cc584e6476d53db80055438e62ca224376fe1eb219d7373bc25eac062fd66a32792c279ef5a031cfccc50979799695b4ef18c59" },
                { "an", "36d394fe3dd9613de84dd72ac64b83c80aa70b39ad594b02cb78dda3232de2b7b2627cb93e707e818eaf1bba276ffb39bff437262541b04c07d1cc85939df490" },
                { "ar", "728839026e58d046a7af8d7ae1c0ed38fb7d2cd9b98bba69c3b19b95b47bb648f25129e36546a3627a28499d4410e4509b42f546532afa813600d81c92199118" },
                { "ast", "30e516896f1696e981d17b1c13406f4acb30aeb5f8f43619f55ac73c18fc745367ef0e7b196c9e7f4584d9f79157c9b14466d019d805f834240e7f21007120b5" },
                { "az", "1d421f7d77430519d0a31eff5755960315b341b5b27b53e7da98053de3119a9ee2d8649060fb0be227df8bf39b001046dd44fd40d139e4359ff35cea67ca5afc" },
                { "be", "bfc9326c9d76907ba6dadecb677252b0ebc3f3d275f4e85df41dbe05bb24f86426c44ffd41bf90ce4716bcccbb721fa8a6411757d0ceeb268d5d6155ed6d7875" },
                { "bg", "ac4a8c9d7896beaedbb89a1227aeaba6f1e0501b3be55808d1c5b038b68520e9b07fdfe9f6bd166bafe4fc44a22c52de9d0ca42c2026c322fad7a969853dec1c" },
                { "bn", "7d7c7ee3f401dd89c21bf3df1aec1d3233ffadf14ca400c32b57cfed71ba20d20ab983c5a427b1469180015a67012bf3b40a7b325b7e3e457d152c90cfe9b950" },
                { "br", "1993532279f7913f7da2af7c463d9665c91cd24811f9bd1595aa7e641bad5c2514468d35deaac5ab2725d8105c68e99d695494755ef2705c916f552479318850" },
                { "bs", "e1f70dd8fb629bb524fef51d6242b90f3802e06832ded7b9ee2a1ac6431e1921a71c007cc87f4f2e1565d7cdda0d3f81de7a639856532fcd9925bc827af83dff" },
                { "ca", "a407d4ba31987f9ebb014c037ae2c8f014b5379542af840c1fa6ca57e58d317b479f9de90c3d03c6c0044b8b43e0c87711085df5edb652794fb2ea46847e4f7d" },
                { "cak", "de5c766aa2bbe780d637b9aac3fc5ac9621f95300374dc001d273130b7eb2e42b75afe7eff0477d3684f574b15628b9afb32e848c4906f7ba2de1d489e497b5f" },
                { "cs", "10b91b33bdfcf8d2274c0189f3a32d6e1d78779cf51c46bc9e520f06c7cec34d11b8ba69b86ff4ca5e0e98a069d0663518d55f3ae5b26214aab458c6f1ac3012" },
                { "cy", "e775b760813e2d93f897da6578c0d7780fd92e1d42a5fb0c08b77e362de08423036f71db1060878322072e29666e64ba92f9ed1c76c3abd23a0da775f3590764" },
                { "da", "e2c8ecc207b3354aaad8ef5e56a940f8dbcdc857a1d256d253e88e33eb8eac179a757456c16ebb909e9b93e42c42bf6b536d3b15d570902a21d935384d582be1" },
                { "de", "e7b5972528ac6f60ae8b5dbd8552f70d7f3490de2c839703cea07531bc97d48ade576b45b461077ceb9235a49a4286f05e49d16863b9e4231236691d08ae260e" },
                { "dsb", "36d47f6ba9911d53d56e292d5427d809f48c10d0889058f4d662ed1d4a5623a52830e4575b8228cd168dc58c0e9343008b4ee81bc030a036d982804c6af3b6ef" },
                { "el", "902ae476b2ebbedb2bff60aa5886a6dd7fedfd36b55cae2d6915119a155b9cbb18c896476096b398a7271e081721b23b80e08ec43599e3c7898073ff03931f16" },
                { "en-CA", "60ba46bb08a1fed522ef561aee82143337245b12d8bfe24dc0fc29a4939e363f6841ecc33a8386598cebb1ec0326be221b87c5e4d680b11f23c01685696b304e" },
                { "en-GB", "3aa0401432ac7a254997416ab20519cb3e648ec4235f2c691e8e1a4920329179ce61f8d946b1a9855b4a132c29219ffaed0e5e23d2825e4eca1eaa417871e333" },
                { "en-US", "a1626564b9c799203955164e2af363eb4ce292ca6957813c9f83c964b44aaf7b0171d0bd3368cead04939fe725e1517e3308be579dad38b7b2ed00ee30430c2e" },
                { "eo", "2ae1b927a630c1870ebe28e3f36fc5af91365a7a7ab271d9f460dae3b955d0fe725ca7db6d95b90551495ae2bd485d245d3daee8ecc66aebdc106a3dc4568af0" },
                { "es-AR", "9ea8f84c03f657162ba3837da722c54095bac06a15433782763a0e52bd499c567aa2a5d4e71f4e3b6bff880e5c0596dc27642008b1a0b3f7b2b1ccee20115c5b" },
                { "es-CL", "4685b383885193a0fb011e05351fe0332d39264b8c0d5db3613091c180fc988c5d83c9c8082f234bc2367c6a2216f1a95b97f2a088136edd40bd77c1b0b92cb6" },
                { "es-ES", "94813ac134d03e67cb91f796b66c0b756a19c3ebb40e62bf55c554cf6134ba9564d86f3176a7200f7f4edf686dbf0fa2cc4cc2413af33f6b97ba9b5a790fb385" },
                { "es-MX", "1b86006a127d9a98432a89789b01b855f061087f7dec470d86730301ed9a9a9534d907e0662a5c171845319089f79049e4dcc998747918d63d3bd452a9509127" },
                { "et", "8b1104ce16746acc0f31961a80c3d639ff140fb4b771367fc3e67ccc6598a8f1f48efe9d7afee587c92799f63d50621ac2646f48b0b996de942a834cb39af969" },
                { "eu", "fe6cf9c988a2a0d4ca07b8f138422f6cf79e61c0b211e7562e77290ad1285f086e8a4946140ea2f5b22deb8626156046cfce2c74c2ffe44db1c00944e2803965" },
                { "fa", "bb72d1641125104f07ea293e6dc0223c39bcb4d3665c86797f130515fa951d3380ce539a703f83b00429333a0837aca5994b12605d282da3414b4711ec688e44" },
                { "ff", "270617fe6d0e004686ec405c124aa45d61b073a36a12ff6c688934b30ec572ccb10746e3d6623e5ae33970b7dfe31ff13a31fda9605aa6b56f54dcb5397192f4" },
                { "fi", "d0878f1f952f84ddaaa55622f5dddd764b308200ac83f5561bb36368a068074fcfa16bfe02eeaac70c34e580b87bb26e8613ef84ebe6ab753c4434616d730972" },
                { "fr", "3550a4280e73cbb5bae00e0f968e87537b6cda78ad17ccca99f388728dbda01e92d9b7786fcd24da48ac6b2de91985daa95f5f457504e549abeefc7e730b6a11" },
                { "fur", "1dbf3841c5df1dcf18896fe35e084d5a5df297fb71746ae53488f353468b59a31c3ad61e7122d8ade8c2b5765a56405d4be2665f242fc629560397f6685cf1cc" },
                { "fy-NL", "577531e14d6b2e3a597d978b4671cf60f818003327703d50137e8ca32ff2492f689b110dc52ffbf1db87a0c29f226f3e8c73a3df89563fe7b97a83dd75363dd3" },
                { "ga-IE", "7486ed712c854ebb0c4dd417e4e86d2415b9482a0e2deddf23f7f62264b096e21a337b3e64be9ee4bae4ec1673517c8cbad0cc1fe8ddbdc466f78eb41e1b93ae" },
                { "gd", "a153e3b322c7a9fdba3831500b79d26c00e5ed5a58ef4e59a38c64087e9fb0b47d7971c40dd26910ab7079842e35200a25d07145a54a67fb4a27d3bd8b69477a" },
                { "gl", "44c18ae4c0de2ff51ee83e936bbeccec1f1d3e0339e017d695e605fabfaa3705fba202179ec0634996bc60ddc03fcd02b0879ef5ce0f7a373765854ecb9b7a16" },
                { "gn", "0130aaf78b14a353fe867612ef9a57905e577a4e0076f4edc3e0ebed7f018e6fac90c2f10af95447d3c1922e0647127b0cc615fad8ede97d7c56da380f793970" },
                { "gu-IN", "bd798871f76bf75fa293c7f97cf3deeadff694cdb19079b066a2c0a436278e10d4efd1a92a09eef7baaad58fae97373499c165ec7e8d4049450338176499854a" },
                { "he", "5185b9493911eeb255a24dc5942b459a63874779fd7561ecee9fa5b6ab361e2e14a38e3d1f21ca7c917a1395c13d0950e6c3b068d7eb07cee74388ef3f5dd7b3" },
                { "hi-IN", "083610bbed8da8a0e69727f47edd77efca6cae7ef0d55c0be848e3e765d142dcdf9dedf83313c78282b5e4205fdc683b0b3ff22adf01fd4f90c85f4fee3909b5" },
                { "hr", "5a331a7774cfc44bfff47d1f8205f881ff0ea38e502c17e8817d75408eeac56a8db2a914e6cad65522bb2ac56246ffd82af99dfc3009b3a50dd43176f3366298" },
                { "hsb", "44118a777105727243cc90bd48f465ebf22488ef353c3c78dcfebbbcf5f5155a495724af8f4fa888bfe1a02f1a733b80d944b0dc08b913a3267e9fca742b94f7" },
                { "hu", "2e1346e399a63b4af894179a32fd4363897fca8d681327c3fca96e8a1de52f474490e1f951b5f09860ae1e42cbd3ddb66a1580f666a182c8de8cce0c71841eeb" },
                { "hy-AM", "71172897602e362c00d2c1f9f3bd14417ec16be3d4595f750d099f774c9373e3e6f864d0a00df005e53e57ddca47f89189f4fda8b9b9269a197fff873b30e2f2" },
                { "ia", "d7a2490518e27e3e5ba77a4e3b44ac1e858562ca3dfe494a9f1f38c768814a86f5a17416f5c5e17a593f0562b37259b4cdeedd035a79575314cd372e88c1b12e" },
                { "id", "ebaea354c825e2e17f1724f154d9be53598a414c5eb973a15d657ca4d470ee7894b752fc122723b7cd6ebffebc4e4595660daa581c5697bcc1036788bb6b354d" },
                { "is", "8ca9216f25bfb285eb8374a15d896e67d4aa17dd752efab84dcf064e5a278ced01c88541906ea864dfaa94ce137b6d25476d60afe2a08feb6b25e0f478d455df" },
                { "it", "3c6360f570b40b790a3e1ebbdcf611eada98366c74d3c7c54c19be638ae031fc4832847087fada731664d09b0b5dd6d4e87d77bb262d7aa518da5dbbe016235e" },
                { "ja", "9b30275d3b41f793014edf182badfba9f91200079714e89257c436d24e5652c06ab9db6164130e8a42d4972fd21326bcf759dea703c515cb712bf87c49ef2698" },
                { "ka", "6b8dc73d8c2cc40959b616e0d4f89cc1248a7f3228cdab9f8cc45c44ba771c76eb97788f3e1897fe94da43b6beeac03061912a4367a894b5d49f7638cb07b684" },
                { "kab", "57bee660a9d10ce20bbedec923331d202ec0f777cff40beab62a7976849ffc033d848d1b8be9c45fec36d248f62dcc279ea9f5ab6adf50b94cf0651996f0e8be" },
                { "kk", "6f301485250b70a029647066506255b55d884f7bfc10ec60f7f85191158d3ffaf5850d68d84a2410c014cc0a51d9a516f0be6cdc616616f7f375038eb40d85ef" },
                { "km", "42b7a1fb7f1846775b73d8e76ba0df54d6ff1d630613aaf3d13647e35da5a7eb69b8fcc7731af08490dd20bf783adc797acc83264153e312abfc9fd921629c05" },
                { "kn", "226f1f29d9e43ca4d2acdc25b43fded85770f970501caa4b717c0072d7bfd58f32f81448c5d254762c0d3a7dc4e3336ba769bbdfbe132bfcddb172099fe22805" },
                { "ko", "a7ea6ab77416a42c27039751e42281bc4c830d898b0d9475348b80d30b1c5f8647084e25bda8060d1d1447ae9ef12a2324c294b2159adadde19a211da11a6ca9" },
                { "lij", "17dd91407ea8b0a0b4aeb74961310dda1532a6faee598cbfeef11af7dd623e38154e0b684ec2c9b98b888d1a5590ed4d6d3664d8b3ac33c3ae27f00cd395c2e7" },
                { "lt", "6cc1231de25a05ed7d7a9c8ecfd65bc24a7c011a6013569d9b08795a37cc3f91f8e7366e09f6e27b84062042d03d42e3baf2b733e6f6e86e5c9538542fe12be5" },
                { "lv", "70e40f376d845e0e92f5f8a2fbc4618696a9a3e33d5d53f57d3fe0c731d4b8e56ce023c50c694cf62690b62cf2ff15e46fc168f3a438931eef1e64a08887ee2e" },
                { "mk", "c7a0fb03d6d1221333324645f3b12db77b64c196ccbec7de792e7cca566b3f5318ac7020cc6bb9960d122d7b3b4a1376aa926ab6ad52dad7076186701429d09e" },
                { "mr", "1914b919aa635781c282bc1e9d8c7b9d7af34f78488bb031cff78cf9f0f929c5c7483acad600c68ad6100b5f0c118d335250f7bec904c7a461355866bcc0eb24" },
                { "ms", "d970720f8d187b0de5b77c4a9d8e3fb471fed96ee417949600ed223cb263724c4c44fa3cee5d6dce977014e9ba8f99edf44a1b35408ac3c6dbaea22569f12289" },
                { "my", "4f3f67be35222cb4327ac3275e8aa29285dcba3c2b53a90d3640c1b28eb8633ad2586fd43dd590f5c9aa79d9bc51be5a3e9d90beaa47566764a6139d4aea0908" },
                { "nb-NO", "ac92497d2584143fff4d4a3a617a6bbbc19ffd9b0bc03463460b4da3047654eb70d316b9a449f5a33e7d2b44588dcdff6b5630ebdb5b59c6aed511466829264d" },
                { "ne-NP", "1aed43891a1786702cd02e5019ce097d67163c47ec80de6c3722e5c645005670017123db35bc6fbfedf94c1e8da86240612fa86e9b76fc01960ab5b01a6d6fe3" },
                { "nl", "8808dbd9bcdcf422266ebaf1a00d1cec93c586c86fb4991dade21b5ec0fe559e650da919c1414182dcf118aa4754ab568a21f40784c43ca62abfe833d2618791" },
                { "nn-NO", "3dd244e937f1d668f57bf4561934328a934c7f24a9ba5d246ee610b7717809e68983eda0b6c8f3f585a086f7b0b45731c2d5a64085df118355c99b0c1de9b235" },
                { "oc", "a639a93176f13b2ab7a176e4f6dbbdbdaef2179bf33e106f1f1579620eddd2bec6579bb5dd8c0bad85593014f33b01a6f68c658deaf163f3186b286aa4e17b95" },
                { "pa-IN", "aa4aa32342d947d5d00d4fd1744677f91a5bb0a142f96759e8cd93ddcd866ff87e67dc3018ce2c4edf7a6735a1a51cecfb4e4628b0e621c9e2c9205474f1853f" },
                { "pl", "1f1d57cae36fd189936b50b901bb63e7d92a0edfca11eafbb256256b6cc52d0a4cfd837f6c7b3d761f2dddd77751b1ae9f765724f1618c8107be89a100c90d16" },
                { "pt-BR", "e0819e50e7321a1e0a92947565ab22167f587c6ed64c2853331cbe4ee9365acaae19793e3c20de3314d17fdce9a8009e6d54f20e32564f5b25dd0ff9f1cd179f" },
                { "pt-PT", "9967a24f0203672fed2d175b517506379693a311ae23ef13c284afaf38b2237a48667d7719fd9a9e90185ed7c4cabe43ffdf02a82a050c76fc5cf6f04c1dce5e" },
                { "rm", "2699d24f8407a66403e7d3adc2437021a1e7b4df0140be6718b960a39577ef0479aab68c5f8abfb5c34d90d7a9885431cfc87e1c2baa17dddce45a48c5a1bd4e" },
                { "ro", "d5761c7ebd5cdb8729d05feaa3a457c9b2d9b9dbfda804b8634010786dc2f0120d2615da19d9659947f7f27e524e14f5bd09c0e1743db7b391bbaecd6e57804f" },
                { "ru", "47e405ee6a2d96ee3c853bfade7bcbf167e470f6eccc0488bd3b70c35207f8588c8aae3777764924aa7379ff18b6ece3f42fd615a8fb08040f52528982ae5abc" },
                { "sat", "6b80f0cd5abed22fd5512c671ba63b682e9335785ea950d31de9f9ef78265aeca26748b4b2bf0d43cee9dd3d5b16b051b29ad438728df182103005a37ba8ce9b" },
                { "sc", "3d707240ed33229bfb49d2c31e715bd5f313db7fdfbb01b5d088a87528e3264a08701db2351f4241eb2710b028387951f468287ea34968a817d8fe15aa56e8c0" },
                { "sco", "6dbc1cef069ccbeda5a1959c1ddf7907a84d095eaad3d2bfecd0b093f72b8d823c6884c0fdc6de9edeb3d8f28d28c74fca5eafadcaef18ba90bfb226dc5a8bc4" },
                { "si", "8a19a4755e30cf3d4cda9ce1b1c39e9aab9db74170cbb3c6b0a054808fdb6c390da305867b430f69cbcc62bd52ed0748f9fff03548337852e385e47ccde0e137" },
                { "sk", "aa4799ed09d606cc50bd4d458e6358c0a71ae93956982fa48e1582a4ab32170284caaf52220787858e1868d914b5069726a12209a31319ecc54ab23bd3ee12ff" },
                { "sl", "3ed61ee03c62bf9ce4f4025075e360e9066b988b627bdfec6d0875281af23af221ef2e0abeb4e5ba826a6a6e7fe30ad4ffbfa9b474c35d71057dbb4356ae864c" },
                { "son", "60b1663d72f7934a31e5b8f32c2f57fcd8531c5b9e2d6e1d531b3f49e747fcd98b172bfc0d1eccfb040082809163ab1729d5f506b4e113bf95a2419f87e172c1" },
                { "sq", "6169a67c3b4c1800ab4c8c0773b07a3c724cc6141857d18284cbc8e27bb187305c3004b0f28844820c293dbd21f36648302eae0f70df5e7a667c30c60138688e" },
                { "sr", "875ea48bdf71050e32fb85bcd6c554132602c72e796490a48b484a4dbe7739fc2da076bc5b30c4aac23023cb12c4fc73d4fcb6d05f03fcc4de80bdcedbc944bc" },
                { "sv-SE", "b1b31955329113055621b11547f4114ab80b5eba323088098b8be5971b47c7fdec9f1b4471eab9b6cdf5b0303f0d4d15a5628960371e69431b4dbbdd43f730aa" },
                { "szl", "db82b87cf96784b8fb2956c438894021ba894bfeee6828a86be311687d6604eff2a8671b78d7481721c8cdd9840782603d81e7a45cb1ad36386c29ca65ee0d74" },
                { "ta", "e832eebdcc0c23189374a97920e2d00240e2ac9fb32f964ae4c616f8ce7f761bb5697d5babc3b1b50cff548cec6ab6b44226d862a1a62e40268947ae475714dc" },
                { "te", "e8f17e83752a59c4723c34d52323111c1f91eda05e87ec6a7e870926f0a30535d0b91589736483a295ec113975248b19679f282ad57df6723fc68c3a1e9042ea" },
                { "tg", "2d97e52f3fb242b52dbd6afb62cacae313511f76f19abdb71fa307206bad50c684b6bc286d74efad31cb5e6825c60ae14754d284222ee812943a31018ea96526" },
                { "th", "bbae125e07ad9fe757ccc853b1ffab4aa9fc3367151945fd07714daf0bc92894321295704ef1b2075c95343a466b46d126d93326306af617cf1d238413b8c0f1" },
                { "tl", "26a1211c04e810807472540f614ada5d131547683c7314c351e2284a2c10b2d26d8ddcfed34d1796c02a4d4a462db4a1a5417825cbd4d15a16b2b775e2115ef9" },
                { "tr", "8c3109aa45f850ebdc98841108cdfb91505b4601e2f481df72b7f32b4a204975d7a5b5f76956e2c394d3645c1042d852b5a58ccbfbca185fa84b9399c87a76cf" },
                { "trs", "acca0f21185b0abcd9c99c83580fff89ad4924faf8390215f93661cf26f315fe1ffc75bc71f32e2a31a1e513efd0a700dbcaa9c0b8cdb5445bca2569b70ad4ba" },
                { "uk", "3753438a31d51dc6628738ea2ab81571cd00f5693ffe928b69e5ddbfcdc2a3bc5eaed001739078dc474a2c769010637714348f9611943e5ff5834f52081c679e" },
                { "ur", "b174d9911accf2c8253d2760215e177f604e057a71a84622a6feb468230925b3a33dac0a6dcb9227c972e7714638ad013bd8aab9143c23cd7c5522ef419fa22b" },
                { "uz", "2a207bdfcaaacf74eae37787c765b38bdebaa41c0880b2da334851624eea295e38986f183448cd9d7a3f9bad444f5ffc33b77bb698e3d8e45785c83b7570ab6c" },
                { "vi", "b7ac1c9a8a873fd1240b64123d21990003a1f1fdc9ad12a2d02335f2dfcc1a64d178a8fd67769885775c2fb301932aac535b8d529e6806e71c90ec4ab1723234" },
                { "xh", "d392bee25f49a81257e45906151c674255496f3254017efccec48f922e851d7b33a13cd6421682d27ad239b7b560e7bf5b6de6792f2c332e22b6153beb354395" },
                { "zh-CN", "82b8dde1bad7e5b63a11e9b887cedbdfd31cb61fdd54bbaa3ad6663bf9a0c97d6c72a8e04475ff61815573616efcf52398cbd3f11e1bb8c91aa1182fa7b6f1e4" },
                { "zh-TW", "bfae87ea11609d88e9eb7c5662c1c6df38ea47cba672ccaef064d2fde459a6ae7c272ab9d829b096786f2e5cefba4133ab8beef2fbd5d393de079fe1dc4fc7cc" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            return knownChecksums32Bit().Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public static string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                return null;
            }

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            var versions = new List<QuartetAurora>();
            var regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
            MatchCollection matches = regEx.Matches(htmlContent);
            foreach (Match match in matches)
            {
                if (match.Success)
                {
                    versions.Add(new QuartetAurora(match.Groups[1].Value));
                }
            } // foreach
            versions.Sort();
            if (versions.Count > 0)
            {
                return versions[versions.Count - 1].full();
            }
            else
                return null;
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                var client = HttpClientProvider.Provide();
                try
                {
                    var task = client.GetStringAsync(url);
                    task.Wait();
                    sha512SumsContent = task.Result;
                    if (newerVersion == currentVersion)
                    {
                        checksumsText = sha512SumsContent;
                    }
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer"
                        + " version of Firefox Developer Edition (" + languageCode + "): " + ex.Message);
                    return null;
                }
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64 == null || cs32 == null)
                {
                    fillChecksumDictionaries();
                }
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                var reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value[..128]);
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private static void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value[..128]);
                    }
                }
            }
        }

        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // fallback to known information
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
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
