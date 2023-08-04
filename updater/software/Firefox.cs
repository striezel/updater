/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023  Dirk Stolle

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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/116.0/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "958ef61444ec6f87ec8a2068306cba2a44cf6180b77732e3abcd1f84de377bf27856ad98758e910755ee56e2f28a82374b82b599e35a725ac36c433e35473167" },
                { "af", "ca835d7e952d47b49fbf47611b83a04e2ffc16f3ba7b444ced38ae33ed0a5085a9fcf4b4564a51ebb4810c36d0514239a80db4f587b155e1cb4c6c2f09536f47" },
                { "an", "17522ac58e8e9c2d96e75841b6f2f7f0632732d2f0af4289c86e0fce99f7ab94a14896c78cd12224c560507f67695c6d5d521ebf377b5eaa8bdac969b108856f" },
                { "ar", "877d89674e5c3748951a3a366a7b3d2531388fa9564b96ccbb8f6bee54ec1beeb5e3083a50736cd0f2e6cb5719776969d90190551c7de8d1c9e010ea5f28b3f3" },
                { "ast", "2b4f8988638584e69f13ff7f50235983f72609c854534ce78ffc7b56f34555b6c54fffce9edeb6169705ddc7d42c33431d3f379d36bdd3b5583420607bdb23ff" },
                { "az", "d2019f994d47fad51e4dbbe0c1804753520d62cd07be804e4465a9564ada980db423f07ba951c2053d11523b8be3ca70dc1d30861db1cd0eefcc0cc9fc84a0da" },
                { "be", "a0aadc2103a7e1a99ee8750951ed37c59da1dd8217bb2db7cc5758cc38f77d569da5c7af9ffd36581455193ccb9d4008e29b27ee52f6d90f438d3c7109ea4516" },
                { "bg", "234af00383289b64f9f3a96a930b29966ba19b3a3ab72417985a36fbaedf13272af143c2cfc725a2a99a2f23648cfd01985b9a797bbf2c65572a41ca5edaf9ad" },
                { "bn", "5d79aaf00237264a24368f2fd2f0d9954c020beb7431a67d57bbcda869fed3c7d3d9a3e31abe90929bf66f4b9dc47612f1fee151e3c8d6bd1e5539180723f333" },
                { "br", "47dbb27190f1093e7335d2482dbaf9e5ba5d1940d3e1013291e181e16e0b687eb7fbf4e634842fb47a550bdc9dc1ccbce129e39901fc5b6e4385015c13a9999a" },
                { "bs", "7e525c9192adff0112e131954192bec735ade6ba4c671a463449e668b76bb880b67452bce6a138a9c7f197778a5ff883f3fac84025e83061f68a17f78d83c9a6" },
                { "ca", "16e68070a38fe9dd1bd3ad60566b77a2ae7a1d65d64949874cc5c9d0e368bc943b02ffa76f4fc007739c8980ac4f90877a39fce3393c795f89bb5004e43c41d9" },
                { "cak", "2d825941bd65397beb421e78258c67ca84f0e63e179a0099092413c54580cff4a94330b81e2176f3b901ebcdd037007f8cc9467d8e13098d3f02584fa1b1514a" },
                { "cs", "e0117cea4451dc65999eb259afd54a33ad4d03b3b6c8abc137302db3238f3eba1757ca30f2130417ee34f307e7440ace29c47b4b0a97bb4f7e160adaa6b95f8d" },
                { "cy", "bf5b0bb8f0fdc7572d3ff4a38fb33044fb990ef5fb6a213cb6851eeaeac61e2185bdb3dd99e8a48e821d10bf5490e48908169d5a13eb584c35bc8b33e55a0b0c" },
                { "da", "9be13796ad482c43c6135a08387a527b1c5d721c2a23fdf660058e8662214d92412aba94c3ee973bc8a69b96a0d629aecceddf5d1ee06dfa9bc8673f24640c16" },
                { "de", "10049befc95a967eb8f4d2040afb873699161652509faefe4864560c38a5fa32464a57d163f34069b9bdaf3b507cb7af6ebce498680d8bfbaa4f3da420424151" },
                { "dsb", "2cd9ebcf6fd01cd6b66de038ae42c9e7b350d68226e56868889084c46e4324473cf1ab93434dab901b55ec43597c2cd5d3441edd88da0f6ae504f66c981b9ab1" },
                { "el", "ee1add28c7ecee2125f402fe33306e16ec08516d6505176fd60b738e84c684a64b0c13748869efad14ab8c7ff35d772eb8559b1fc03ed083cbc71b4edee84d7f" },
                { "en-CA", "010b1fd2991750f55a1ad8a6738f52cbf021d4bb2d448e4c0bc5ced5cbc3c38604e41b331e9b20f69022d3d718c2e687a145b58054e08ab5e14f79b536fe89d5" },
                { "en-GB", "c74907da800f1b2ed9db06f183d684038ecc4d0bd4499b0323b9fbd17987df547741f45d5db23e9ddbe978f3fa157318e0bfba2bcbfdab82f2b7cfb3a3d28dda" },
                { "en-US", "2e29a487e13669a0bcadd0dc6887cc426a7d6bbba38b447ea18b42dcfdaff6f216dd2570fb3730bc5bb4d67ee3ddcafd5f417a8a38c4a2fd147a1c0797400a8c" },
                { "eo", "c9b0d5f479149a5273a667e884d57eac0a20e67d594b472ce09c993eee50f7a515710041d21ee5736db74bc6d39d3cc0fc5e67518999e0809f748aa152be8aca" },
                { "es-AR", "44cbc7e8faab900fbff6ac9e467b19844b9dfd25173eaf87fed45853be8fab4178d6081c4e1a39221c9ad52e11948bec56bfa90e583a370d28cf28b60f941161" },
                { "es-CL", "d15ea6219beb19ac284ddba26d02c4f255806491ad820ee0a7de4765570cdca249f42d004ec4651960395fc7becd5277151b9c723df713fca1d8d43fc3d29831" },
                { "es-ES", "37f03355db7ccca9aa880e7fa5b806985baa71619a47422b0c5ff297e3cf2157d1b38f70901e9f26b93e0aff713ab4062a1a57ba1a13bc25ce61c45b30664df5" },
                { "es-MX", "9f06de4435bb5228c7ac3b805b9fcf09b68473b8d364b0ef57e2f96ea2460ca76d416e464d1e9550983935824090c5adccc9a823cba0f1801dc418a3d9a0db3e" },
                { "et", "d2ca377a32f3476f2b3fef177e586904d2221e261f8e20cd5b0d2f5309c7373675f4b24a7bfd87ffc3e7c01a9e13760a4d0f86df5f22a1111621734cae11a1e3" },
                { "eu", "c831c67f78671bf34a3ad97cdd7ac4fd71b31a412eede0c04db95350517ee7295a209a6edb5d5e32116e1b22916c24d4a64af3f1155c70cbfdd410fe1d53253d" },
                { "fa", "bee44303aa71f4725caea626b5e1d7223898fc8bf7d3fe8a93761fe3f19a9a9b6366a00f9b485a3ff585dd625311a83ed201fcaa4db984a9b331c7cefa9a3831" },
                { "ff", "f07166db17476014e4df727c11dbb867351ac0deab5543f69a51400d660429b86d30e88431ac2d81499e307d37b21836c8bf4ef6e7541d10d851820b0b2fc854" },
                { "fi", "7c7249bbecf722f455c4e208dcf7e0d283e9a2403d9555d49f548c8eba0304e5efc23107e739cc5a116b81896f88cfe4f387bb07dce881682bf892e39130a5be" },
                { "fr", "6f7b032651f3d60434f057bdb8995070057208370f333835dbf728844bb6eaf92fe1d4284c1e2253fdc2a34206f9cf6805a644698e35ce0d491d843af95031f2" },
                { "fur", "e5aa0aaa62a9c01c1a6dbee9e7e5ff8df37adbda75465e525188f2d035cfcdf65c36b98f9539eb049220917c896445527f537d9f9bcff030b1ec4487c829b6a1" },
                { "fy-NL", "6b14db89d9c947a002384bb070bec8c2926b7a549ce0ffcff9c901c1ffc97c2d5d283be300c33fab74e481bcd64acd55fc7fa06f836fa29f8d245bf48cd594c0" },
                { "ga-IE", "5129ef94307e22ccf223383a7638fe14061cb64d351f136e84e620497658448de8716662d2d5aee70c51ee825f41ff00e8474b49a6024d34d9dbc42b4b60e34a" },
                { "gd", "10a5580a5883c65d799fde0b780b2b66fdb81e5f987951c160a2fd5ff32cb3fc27c1febf6fca403249f52afb22a36777d6828892533f6fe9d6382b6229115280" },
                { "gl", "d41a5be8bb5b068c407e929f9d1354c0dba4223d52a0d07923cfc868785806f3ac6b84c1d402505422b56cfb9e0407c54aa112baef0f0bf112f809ebc23d8a85" },
                { "gn", "4a3dd672f99c8a678ae947df79ae852496c940bbcb72682d3a125b611e6337e1503b82eb984c0dff3bd4834814d8ffd7387b0385f71e499d19f2846394c140a3" },
                { "gu-IN", "0d5b90f2e9d6e04b6b68eb89e884813ce71979b2a74a0c263be57334c023fb08d177b92e32e14efeda3821b87f33308215e5ee3fa5c0e131e5aecbf31fadbf50" },
                { "he", "9c4336ecb3f4d806a2f493f8e0b66b7f4c6ccd0e3f35844132a436b23f77ca0ff8456bfd5de06f061d0be306a68c4fb8ebe49b779d8208a0070f223be0f917b0" },
                { "hi-IN", "e5c5581d12eed027474abcdae0f1a172e435e43d1aa14560cfb8708eaee6fd0de47dd873b036f8d64d940a043dac6747b6736126ccca4ede261ad36eb954d915" },
                { "hr", "f62020c51b82dbb884d80d7bfd5030778401376f5c8d60653744bc485e8e6b169790a8c89acb7e4b54247c51dd88c5f4db948c79771b596a41e2907a7227b1a3" },
                { "hsb", "396f574467a34a03f94d595f3abe8c6268582b103ae8fa7d38ef0c1d5501455ca89b567bdc48432a87845e286663cc122383ba9a6fc32bb3592e9836d812da89" },
                { "hu", "e12a4ac578608309a39fe17af7da15833c6ce3d82a6b8f9a094bf7a2293a49ce9b934087178ccb227803b6d1e37787f93d587df9a7bfdf9ba08d2b058d2e863c" },
                { "hy-AM", "3fcfe1cbda7c5b22125da3eb03518c4d818b14c94366b0d0416f43b5bac423e5525376be9e272808bbd756c4df92ad9419e3c9b103c162d419099223a8cac6dd" },
                { "ia", "861ab3cb85529f628b7d5fce3fa4f5d548c60636760d63796f5ebc031dbc699226ac1a902793d7966921265b566c0d83d6081983d233368851f51f81e4068ba3" },
                { "id", "304dc24f760b2043fc60ccc1787bfb68f541c40a5ee96bb8826383099d8de4b3834d31c3dc61a40c64b5db8cd982095fbb5cb7458ca59e9d4469b0b378d86d22" },
                { "is", "c11b521875bf60fdfd1feb0ee484949ab191d6529cfff7b160dfc273bebe699f70863c1952675ffadcab0dbee926938bcffbb6affc57d7387e52203374d58cde" },
                { "it", "64511d46611215cea885da3b05f93c39c44978c0c44fecca064d0b1d282f620c8eae69492fd257730ee743066eab6cda5099cd162dcbfa5e60f03ff4271dac4b" },
                { "ja", "b4e2feefbe2be3c8e3344e82fcfe4c7e868e7a74d3768c27d2386e1fb50dbc96c998bbad3a754bba5fd28f086f68036aa8602386751d012f330e1b2929cb8f5b" },
                { "ka", "d7a3a2989348c1d48270d6c435dcc839fb571f3568cb90d51147ea28b8b59fc784e8c098bc847db3cef4941e0452a081341e2fcf2caffc9897fb95df5ded81b1" },
                { "kab", "ef24f3cc92987fc29e30d215c535221be75eded03d0bb7afe362d04a442c8dee23ee652102ed3ecc4dfabcddfa103144c9b24e3e4306d7b8e1c03d69292d2a3f" },
                { "kk", "2bc575b699fc9268efd985260c7f0c581081a2e0edb3b28fcab51ce3fed09269fb6b7c087a2ad092bdc0fe403bb0a51daad139fbb5d872739f5f450012f2bec7" },
                { "km", "33600a9441ab3799fc1f9ba8fe53e257905a3b21f7f468255350f8a8e2128af480ede1af1b17538458797d9dc8641de50d358245690aa376fce544f96d03f408" },
                { "kn", "71839169767a81d3931036bef0ee16a318c3addf92883596c5b32bf7abc36809e5b9877066108b7205778264b2dea47dbb3a0101e90bba8f5717347fbe02aa6e" },
                { "ko", "e702fc77ea735faf5b36bcc8ea5978133f970a09e5d2cc1418f946f0c4b37a2a0db58c477c3427643fdc95e7e0a1c070ccdaa74d9a234dd2dc58625d719914f3" },
                { "lij", "4ae76c02b8f0d0c76d76ec5fa119cf7b250a91f8804fbe3381649fae0aef265bb391949dc74b244f91857ba0377525cfa0b5b02b71c81c54001c6866155eceaa" },
                { "lt", "3538480faedf7323b3396edbe0dfae07a15624bbe0f6cbebe62127bef96e2e6c06c53e5572f92f6c2d1f5a62120639d58767ee2daaa74f3ede4cd01ecc08b9c2" },
                { "lv", "501b2f1f4041e7c03d80673638fcf1c920a8225eccf01b50c60f433f1d8d1f07e26f6101b65bb7ba36d00553ef0c22827d976762a79cb535d7c1a5e8964ecace" },
                { "mk", "7ae1ab9929f24603b5737d5eb0d17ca4e5fa5db0e62c0aedff5e70bd15a6250033f72673cd499e52da3532bf3826a6ff9dd4bcdb1fb452d119d9fa2de1172363" },
                { "mr", "bf6eacc3c05f84237953ff4a748becc04e0486df80903a931b26ba912de20ccf71a5403e2640463bcff8c8d0d71e331a2467421f5ae3429f6dee42ed4b1be247" },
                { "ms", "d51bd133b1614f0a26ac4b418a9e9c5821ce4734ccb81ed4b95a4fc9251ce1cc57a42340b94f520c820f27c9e6570be08fe09cdde646f9303d5db6d40e283af5" },
                { "my", "a2d346ba7e25262f6841bb85fd916c33d911517359080f817dbcd6066dd9e66f3ba7edf828aa05f0a8fa76f91ee85b99fcaf08322a68856ddefe8b3ac68f10b7" },
                { "nb-NO", "252d24513901e40c36f904dbd13614ef4a08e37b81cc4645a1fa52810d6f267b15bca084ac9d85d658047c24886fda6029fc398e91caafd4df23185d7a4ae304" },
                { "ne-NP", "4c60e62acc0def3ff1065d73995cf18bc9ef0c24a423202414432524aacfa09b0e3aeec3c5216e8a38a4064d1f565d3dbbca57699f9da58c244f5a8773d757e7" },
                { "nl", "1a410c2d408abdbb470b0cf37d08ad7705d2b73750d3e947e25d0d5abbd213c01fcbd6b7859bbda7441fb4d853e70c7b2c1fb2aa1f57e1aea00f6d9070932109" },
                { "nn-NO", "c7d2405b6389d94b09a91e34c2ec0059a1326f244874516997b0ff20fae6d2298bc492fcf0dd60d3a3fbd7525414d8e038d328b436c7c3369f741e16193ed6ce" },
                { "oc", "60158d1bcf5e257d748742f1d6dd24dbda7cc94d381640ddae42ba62de60c61d7f7ff1a87e08ed29536f9f1c4ded51bd62e341a1cad0e4a3b7ed33c7e4ec3cc9" },
                { "pa-IN", "2ae2cca66566831e2f749787e8f842d292fe80f7dacb00808850d5192bd7beaeace307036acb8e66dcdbef16ab005e078f0df39d9a058997025e2431bcc3950d" },
                { "pl", "61c9ed19bbb51575aa166f429484698458b330019f7159014f3b645176f9807ea74ff99dd9f4217ca4fa78c6467c223115077328b4c5529b96a52e3696a8d72e" },
                { "pt-BR", "5ef5fbcc50ceae2849cec91bd1e3a9b2727594a8dd80140ee3938c28a5758603df733c36ab0af2b83a8d300789f1e676515a4d8415d8de2897d7df50b51bba1b" },
                { "pt-PT", "c2c9694f16c3bd74bac7343b9e4980911e9d9b9afcebce99c9472268092d9a6a878967807cf41f91c2d7ab80ccab9517f4543626080081911faa871ef92e248a" },
                { "rm", "ea8929aa9302c759658c50eb3114a8ca3247066e68179199eaa59db2e125376223a75b2403e0315662a464a886346a8f33a8415c983eb6cc2c0a424d1c9fe180" },
                { "ro", "bbe611b0da988f0b61e1e144ce1d9365835877ec8cdb9264ef8e439c5c4c53f2ed32693a08e7782e30644f9a682ff1c2546dc3ad61ee38a37c781403becdf249" },
                { "ru", "336e9cf4d2af493e52747f59ef5e0fb08999e34172c7570a5000c61c99e07bb5bf335e3c78eb03679d581c2f1d63e68be4c4e96612cf5340923a7411f090748d" },
                { "sc", "0bb7f0fff31d164fd7e942e4fdf4bb8d7bb89ab755d5c0f8690e892a4f85faa7319c52acdbb2b3fbd328707c0468683ceebb4e5700dc0e83ac9f4a9ccd76eb58" },
                { "sco", "323d0144e067755ca5ed49d8ef2d7fc1fca7a1bef33446af30d41e0bf2901ee90d7b8274610753b1a35d4ca72c68f06b0900c4c1219b727543976523ac80e932" },
                { "si", "fd631597b22d02915b87f18f492e4e72a86202c15d507b24802190cbb12a2d7d68bf4a19308fca2e8c659900a0fc70d38b4ee5a1e9b23961a8b120e999f38a00" },
                { "sk", "0516b1b4dce40d5c8599d7e781da3df2bafc9297d25c4c6b905480daea80c5fa0221f3411a7ff32cb3642ea61008a3d17b647c9f424adcbbdcf6ffc6c0952195" },
                { "sl", "5121381eab0dfa78c2641019563cc4edaf04d16538db4f45a8d6d08a56bc8de5e568a64d2f3bfe4087b1dbf7389a0b3a1ad3922886961233503e08c4ab478e85" },
                { "son", "cf2883b482877db584247b5914fec12a19500c859cc67618521831db7ce8ed522080806890729faccfec2f4094b76dbe12bcf60e4d86239239f4b4677c5643b0" },
                { "sq", "bf09bfc2c32c07c4feae106970131dabc87526148743a8fd6261ff51a6b37b9e00839b127b35503ee73712ec62dfd30870cd630f4a6b00895754cb9ccc073f97" },
                { "sr", "33d9abfbc42255d2e36ea76ccffb2c9cf99006dc41c4b8accbc20b8fe2f509ca4ee8dbda84a2232fbff8f9e80bf7b1f663a8b97fdee3dd1f56f28b26b5c2fc9e" },
                { "sv-SE", "166d44441e06a5b75915d25bbe20fd9f75232025967bb3e793cba13d2dcf8977d0f1d2d448d4190766e53c5baa11fa244bdc3e6ea16c4e83a5cf26cc00c7b096" },
                { "szl", "dee942c86851ae9348caf6fec5e16ea4b63de4bd970392893bbfa5b1dcb3ed9111bfeea427b315fe1d61a09827f2bcc6dcc212767264c4453b19428f3bf4ac64" },
                { "ta", "27d6c10b8de45bae66a06460ca30167efd0a1315d2025eee2b3d3f4c74b8198d337e9db00babbddedb27787bce61204532bcfbd6e6964c788b61aa606e415ccb" },
                { "te", "27d99ed4b0b0bff437597c086b24e364830e520d74d5e72299aa5613bcabbb03ecd4fa8813bd053fe96334a30e7b2d0ca86957d16b6031828cb0013d6edcd661" },
                { "tg", "0b98a20a5c85717f010f89cda137e287e454e63fc364a1aff0a729ca402575f7831f4211284f844437a7161a108c012d695339b5576deb7ad59dd67780347214" },
                { "th", "c4303b7438d8a64ee7fb20b271f1d8ebab5cdeccc803f612ab56346142442ca738f16f9ffef08b4ce43740a0d868a3406c1e07c358bd43cfd791e7ab1ea02e1c" },
                { "tl", "162913edeea9c2b13b5bcab15d9ae367a226d9e38bf16c87eacde40cd4ccb757fa7f0f0edaa01d6855ab90d7561e2cea95b16b700dd22f5ba7024cb5d15793b7" },
                { "tr", "5719e8a82bd6d78d7716457c85fe6f61d383588786a044671541aeed15e76ce87cfda14549515c190c0ae8bcaf11f4b784a5105e4bbea56a40e7a717dabc97b4" },
                { "trs", "17e51d4594634a760e8c37df986d42773f6ce371aaff1e670e7f3017a301bf69be89731a94fb364704badc57b20a1c32b3740f01db45c8cf972cd06efc5110d5" },
                { "uk", "d5b7ec3064264ee54a48ed7534ea065e9caabbd146467037700f13b63da8b3292912e568f799fc966c525deebc1645a045b8bb3f5d5d99955b5bc768569ae3da" },
                { "ur", "4ad32396026bb6a54075db10da5b484c2211cedb3b700608cfcd6366181c14f05d0423d4248dc6732e25c23ffe94cf47e919f8525a40dfd756d1a640af100bca" },
                { "uz", "82bbf78b8c01976e44e6e98673d8935981b90286f7b73d8bdbf4e37f8e8efc05d4f0727ea7f84a877aaabd6d32fba8de86cfba1e6820dec7b60dc2abccca3951" },
                { "vi", "8039a272a62538cff1e731c395168192a3ea82b601c4cba1878b0865a5dd9d643abc7584180ca8ff50a4b23e991dc3e84c6b9143d022feb61ebcfb47ab067744" },
                { "xh", "334ded2362994d90cc1d4f10e6c66208e64891c87f3ee8412e54fd8a21af4b7b4885ece36c9007d4178ac7d8a585cc31c132d70c6da058ee49b7fe1523301ca8" },
                { "zh-CN", "4d19c29b773f8c5d45aa33995b040b4cbc2d0340c41e8dea7330ab269ec005d558e7983e043fc29228042ebd54e6ab024db7e8a41b90417dbc70908104a30c11" },
                { "zh-TW", "df2a1650f0b0affd7e8fc1c81c5fceca4dd957d6c64d300464464330e9f3135d11dee6e9d442f19aa197931b07e80e6047553f142bc46984feca901a114caf04" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/116.0/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "af6fbcbe56dfa6dacc82386f28a4d7432c385bdc40fc15fde313f01fe9b08adf94e9f4aa55f01ffa1f6968ba9213d138bb0ec863c828f67e42e7651a9c506e48" },
                { "af", "066770c2d7b107dcd41fcc0ddb0dcc52a3f05631eee4d4ca2f4d68defa37bd8009c0d84ea4368f47522eef486c1e133d51b8efc5afc360e99c67981d162e6df1" },
                { "an", "ffd4e75f38a866a8ded4a914e66f6c81a01828863253b9a2a3ff134fb70401fe27ac1ce6034b60453d27a2e70389410f4bcba396e3ffc576ae7b98bd4b0e7546" },
                { "ar", "a96d827ec3d0798924c00c5a8d0d891055d0e1c35887b5569bfe34f9c40b8794896ca0b03429eda0978eaa2edcd998b1d8fbfbb23fee63178ef941dd677162ed" },
                { "ast", "e30fb610e13af6011f3a3b8faefbc39adfc1ff939002ceb44e243bacdcd14033950848db8cc3faa07b450a9ede1f1bce506a9c15e5d0634199adae660da333c2" },
                { "az", "75970336a830380f4647f66d41214c71a93bfc1d5fc46efd60dd668e62d8d1b34225053e1529157509bd14f8733358219375d15899b3693160f580cd032828c5" },
                { "be", "d416da549e70428b1ffa232f1f306ef9259be0878ad4c7270b569b2ba4f838643a410656c40638e5f7631ef5e90add0aad0a3caf354f2ab96d0e9b530e4cd8a7" },
                { "bg", "b4b6362dea9d780263a27a46c4d38dc16cc5a340e799c8461eb1514d288bf151bb366903084fad6429f7d0b6b63342bfbcd494883ff2db494cfc5663edc4dfe5" },
                { "bn", "e194bdf6ca40d29ed5399c8c2d2ea7f08963b31900f7d4d9fcfc97d8bdb027b334128bf7fe157774de037a3cade7f23fb12fc4c1f37d1a6bf15b1d6e86748fb1" },
                { "br", "794ee387cf808068af02ee06ddcad93513f9e0d936ec7ea5cfe86c08c768158e4e4593f7d52dee5f6883473fc780eefda49af59317cc6943826bf7f5237c0b9c" },
                { "bs", "63582349634729389db98a454aca52b5763a52f48486f17d4bbb99c14e26ea4bbe3d15b70907ecf8239035d6ce0382a8048193e3c008b77bf6e7d0f275dda683" },
                { "ca", "14df0961e356ba7836d7fa573c5324d33c0b0d1685f96520e58d41da2e26a23be4498e11bfc3f7353b80567718267a07e2c91dad7760c8851c9b9cd40c596ec6" },
                { "cak", "ec12793d0e379cef6c87c7e7d61fd064087a55ab946931cbded4ed6bf0b01af3eaad52db0cc934e014249ce09947871585b5052db8d6d017b02a3d7c7379ab56" },
                { "cs", "d1258db188da23562461695fd6a8827005b17b3411040b061de15de1ffa0a16038c0ce6a1dd877873f2c66b5916f1910ed68c55c8a53d75a9e20770447c49852" },
                { "cy", "d1d32cb5451300d97d8ae5c878c3c40f05b66cb7e6ba3e0249ce11bb6fe2289d97a97c12f06ce04ca35d79d3abddae821b85d97d60792977721c53052d33fbb5" },
                { "da", "801b77ad0ea793947675986222022243ceb41484b7809530684a537224e3ee85aeaeb041a20adfacb9b16d4f8e29c851c6fb094322c2160de292ebdf818b1967" },
                { "de", "90fcb4a903320d71590c82883bd27898c2ad6d0eea10e676b6bc31ed9e4428abc02e5372ac3aab355277fb8594913840648a8aef0929a145677ae2cb3f274b1c" },
                { "dsb", "9a3d6201b91eb8e61fb16b0a3990df6c514a90446500406f4cb62de9555a8a050a91bc6a9d6fa6016332ecbc8ba7f5fcceb450b00c28bb554e97fd4b4040ed3e" },
                { "el", "df2f345229f45a737876e1bd15e73fb03369ed84692cb371fcb6dc82c1c20cf2609b4303bae7481baaf6ffdbc2da508066aba673f73812660d90dc8fccc1ae57" },
                { "en-CA", "a131d1cd2cf1fedf3a810017cc2a70baee250871a7ba7f8295bc229112a0914492316a1188bad9a6277a87634bac199d5d10fd90e13270eff4fa2557e8080edd" },
                { "en-GB", "99a16fdb65e14724f68f7f1fcf03fbd4c1ef8a2d416d3475b38dbf387c17d57fa7ea717be3a6ddcac8f141f725cbb08b1ee5227b3c485b0fbd235063bc874d23" },
                { "en-US", "723d67faa7f917d21230cbd2dd41db4e0e28fda00d6607f7bacdf484e1c7c0a6dbd16c36f54e97b93ead8f9c8558878c036b7995c33e75a0313013bc7b0c537f" },
                { "eo", "b815e741c36232fa9ee1fe978c78ca4d40abaf1d26d5742212f11c6add0865274e581fba0719750e452592b27c71bdb16ec63a151097ac89fae43bc7955f5932" },
                { "es-AR", "d70cfb66a57a841862c09b76379a7c6d5b49d578b94d9604c68eca42e6f71f02c1ddbd728e7abc99e25dd9160e7aa1a882804fd95987119db6910535817093a6" },
                { "es-CL", "abf939472a03c1ff49843428e40b22d9e4adea3e76fe1dad0fbf02b2dfb559f4699ce30c44d29c2135fde197c05b7f6bbfe282e70994f002e0f950a0cb3099eb" },
                { "es-ES", "842eb70963e2e4c54c829a7944f5df4ce82ee9b487de2ade7083beb9b65b2e0183b697378cf5c0e35863d0b9bc9e0dd2331fae6d3a7201fd99ac1cf84f73c19d" },
                { "es-MX", "9c494023ebf5672d9e4dbc1cc2f8dc63eccebc60d9b9ce1dc2474fedf3eec1232bf2185f0aed52c809f577470ea37bd02d95a35787981961d8ee5d53d0550512" },
                { "et", "0571372ef990079ac8dd7f27e2996a4227bf0a8a2fab208f400b10afe99b7432bb06dfb2e969c3e68b823051acba459ee61186c7cbb73d28a89d43acf7951c3d" },
                { "eu", "838ed6754caecb14d403a249fc3dfe231ef00fc68ff9690fc9c611b486ae8ce7131388cf452ed5cd6ff90fb5ab49434c01dacae9f0e0fa287e3ed6059121bcd6" },
                { "fa", "aed2d0f95546b3ee0ac8fefddefca878589e9b319e2796a904cc538964435204b8c5dd318bb82004df2382f13e851e1a27d49209374e82d358f5a433af89682d" },
                { "ff", "44572822a0f005100d3eb492af081d91c87d7009bcff92839dc1763807097b7491d09d89669bb42c22e63a5741346f1de5e2d6b668646430fc3314c7f26bbe92" },
                { "fi", "05ae78188c6497f3b15cebf96258776ae00352c4847c8998124114650c8286429c05436ab181ba5f7d9e05b15cd262f0eb21399833c9ee7ae2d8110c4a74ac6c" },
                { "fr", "d6a5fde17a563a530b3bc1bcb0cf39fc82846a869196174ae6baf69289968f6bce2a375f2dd4ff5582ed3bb08e828011d457f142ce927f1deafa2a963b4ec559" },
                { "fur", "c1c63efea1b2135c8867fa9d14ec53db8030ddc4e1a37c328a43646f02867c8efd0d929db2426a5f9e88f07c61ed9f56b88dbaa9b3ff2f90a87f670ea175d262" },
                { "fy-NL", "dfe093792a2de6095fdb067a5024187e2ef43fc9bca8c0c5c95640583214197059e7b951074dfbc2fdd00430871f2d707beb15c8f3a3a3a027cb6c702c11c85a" },
                { "ga-IE", "658b7d3506030b6ee0aab282a4c2528c340c9664c2f942ee5780aa00dfa9e6c615eafa1f268de84336fb32ece0568737df17ca50f5090d090db47f45cf5cb63f" },
                { "gd", "bd7c70cabaa27448d46e204ebf787e6ca8057fdbd058b14e36a9bc4d4abdc0f2b86d192b9932fb4ba722377c35a123bd08cba275a0617bd61dce399cb88d6b56" },
                { "gl", "72f6b9c3846cb0286e90c4ac7fa23104a68d9e4ecc4454c2486a92255cd8b4f3c79e4b19e51163d057138dddf82a3688cb863128f93b20772782755d00563612" },
                { "gn", "c73a89cad15d4ae8172ed780d6ea765b9a5d34f4d4355ac7ac790f9cdf519d976946f5e5feb86a902cf328177d048962b35ca65e8321f095c0756ab5b9ba839f" },
                { "gu-IN", "7070fb317e5a068ec4e670064a76b1b4c46309c8374b2a781467cf93e734986ab36eee44b530681726f3e8a78a9c5648a6e1da92e8fd360bce2293d16fbbd4ad" },
                { "he", "551499bd7477755f27b4245f4c7bf911da470a0721bdd9e66fc281646e1702969856e3fe41a84d26f7cf7d68546838de82d739df2e6065e051b455d867b08917" },
                { "hi-IN", "bae0149bdbfb479c91ae3ab99fedf37b96a923a943a01223cce907640567793ba68938e0704c6ed0e1af64f028f224adb9f94d4b8f40cd30ca208b4843ee89ab" },
                { "hr", "3ad51f239d69fc035547378b35e5bfd17bf5155afac9ba444c1c225cc071d914233d41d0a3e470d5364276d85dce03dcb0c67adc07218832d95288b48e8ee0aa" },
                { "hsb", "976a8d15ac106f615456c445e3643dec10d46135feeab488150a5084cef252622c06e3d89d3d08419700357f66c622ceeb84b4ac18b6409828f83e42464a47a6" },
                { "hu", "dad5d020b670534a72377d5316f1e80c25984aca2023d6ec9bc769fb048c15f252da7b2ac1b7e1d4668d0012c62d37268c0ff1c5ef1703c2ac1c6aad7c4567e0" },
                { "hy-AM", "f57a87336ebb2cd12e3087de1f65f6d5a11b0c07643274d4549c9dfe65402bc191328b7e67e0c1e8b82a6e11bd6f70cbc6cb3e1c2dbbada3834619494d9fdf4b" },
                { "ia", "82703febe271e6fdfde260966f57cce9ebe91542c676c17858ea8a1e772cf8af7a0f71e54804188c8ea5b0bce29383cae51ec6bbdb21529b2d1e2a3c1344993b" },
                { "id", "65a7632bb759486e4cc461fc8525bbb472bcd15d48cc05a909c8e9bbac67fbb12c8daeb38cb1a6584e5a7978fd7554a51991524770de4abb33d7194adef6e9a0" },
                { "is", "0294601cd9e3d11b23114f7fb3aaa96a0e8c4ad9385c09f95f3a833d7d03d148325dc2ff765cde27ed0f519c5c33764bca31d4f90d368641c105381a4e346080" },
                { "it", "68d1bdf83a9377ea7b1db4c6b8c059771c789319e26eeb75726cf74e602215970f468435b1b360e2a14b8c8c2c12f03fca6f5e36b8ad907af42006bda71858c8" },
                { "ja", "038c5d5de1800bc97870ca071a469d72068a9f320a60adf18085c8940ee86ff6e41dfcecf7068a2a90522b885fefd0472e1607ae8ca3bbe4bd08e3dbfe13d068" },
                { "ka", "864566badfa2c83cfd9487327ce90989571f80c994e5fdaf4b06f7c05bb5f4964d2d562f493a027b5f0bae207deead23afc1096abf3d794266967ddc66409fb0" },
                { "kab", "6ce3f524201c81e933df4428ee1f201ae28c45f8b9e0caeb8923f74908f3f9aa288f36f45caa4e48b10fce658537943c6d8bc55f4bea826f00dd0e7a4c94ada8" },
                { "kk", "bd69dee658cf43dfcd0fb3c9e11ae2493f29329cf836601d6c2cefb9a00955fb92cae04683746da8488d0f10507fcf1f4556a086467ef5123f0fae07300b4131" },
                { "km", "a1c9c71657e1e480476af64ff0e3205b70294cb2f4d8fae8cf0286bd0fcb3fda9f987869a601185c3c177ff5925cb8f2216c4c89657554ecba753a3130936da2" },
                { "kn", "09e82a41b6f071951d78b1529182659001d6ea308c8c31f7ea88f95d4ee390d729b82f1e158b349dadb2eff6f54c6dc2b5b39630d634ea6ade94271176614b05" },
                { "ko", "fdbff7e54135c36786c53a58ba7e2509f8b96ea109d3456c6bbefe3cbcec60fdebff2cbf6cac50a51b9f91d0b55a1bf5610d7e7e0f8836ebb399e7168639a2c3" },
                { "lij", "367c9df981c34c014b88d2609f2d326c52fe04b3bf6c776cd95be205cf11457bd7ed6396b5d44f0dde46d61dc81d2f77e763793938ea83f1606c63cf4a6bfc03" },
                { "lt", "ad3ca95f6146e06ddfeb354a05a5364ba53e36cab6967d4e6dba6dab34e3ec4c83e40b767841651d70d394746343ee4b3d2b9f6f309200ba14bae5d49d27d045" },
                { "lv", "c07f5a777ca155539c10aef84f06180990c97572194d7bcf39fabaddd21cdb923a9cd278b3bfdaee151a46d6912d2790f0c4d2bb64fe1e4c4cd58e6745257c79" },
                { "mk", "0dc14168976671ed6a95cfb556d4fb02457fb3c6a5f9a31a7abebd3910f0f30d941e7a7a41be008daefe3a9aff5a6e0116a20cd8d6bc45bdd324e22744205232" },
                { "mr", "44caa6ea69b6cb2c9b98c86b1a10c2372dcd192933db17beb162c2bc9643b387dc98ae4c2c0081d3be72937b9e2c04fb8582c75e9b8e41e3cfe2f298479a6bea" },
                { "ms", "2b296722f357a2e8ca0441bceca63ba861b4d777421240033208f1549c24dd4adcf357f50a9efe0cb673eafc49c488dcf9b68cd2a0cee089ea55c4bdfec71d0f" },
                { "my", "fb03bd63ad507923aab5a56e6b8a2f4784bb3484f4feddf4f1d22814843dd69696970adc8b3310c3e4e40ef5bf6fa4c4c99c8477ed49f6e54459a374cba60cc9" },
                { "nb-NO", "bcc866dca904b17e621f856fb9d4ff8f7c2c799101a4c502139615cc2918b01480c506aaf06e3c96e3d8e0f652355d82253ce2a611a661d8b757c21ef199bd27" },
                { "ne-NP", "00e23b4b48b7528806ce2dafecba08d91c3cf33d82c7b78eb755fd2aa9570ae5a5d3628aa117808ee19043876d725c536e1386eb5ad28c82d7ac6439ec049f9e" },
                { "nl", "ad8e1082ad08206ae124b3990640bd34f49a312e0bfa90bda52c0bca23152df6b1c1382d5636f6908c10294157c87e6268147c19fb887cbdec82b8d116546a73" },
                { "nn-NO", "c4f79585e2635c645f6baf12ccee81f5ea083f6a168526a018957bcac68b4f08193540cd08bc9dd6dcc9d19c68db877e9db9782c68f34111178c1c990e7aa48a" },
                { "oc", "13a35c5f3eecd6d9a45abf2092761c9affa2582a712eb931d5dcdea4f8e28416fe64a094a5ab630fc57784a6fefc645654dab5c09e1eee68c5f77627bdaa1841" },
                { "pa-IN", "6c3fa41e62ffe929dd05c9ce2643dd71cc4c6ed3781f003edc90a5cd85003670a046f460b6a01b059bd17930ecb099d740a6323690a77f097d49f8ff00aa9677" },
                { "pl", "3d9ac82777e926efc07067893c5e8784353ff60691ba790e0ec66186e04f0253b1bd9d6b3fe2fca96f2347563c2bd6148da3b945ebdd5099b8cccecfea64a36c" },
                { "pt-BR", "d74100f29f1c507e873c770a3bd1562e3e72ab2aa210d4bf8ab389c17c16e529c859fde81d3e79b056f79cdb16de5ba234c92855e571a99b92f4defc87196a17" },
                { "pt-PT", "7f21a004cce3019b172bbda4aafc8bb99b9c5c732cbe8eb0cfdcd23a8c35633bb9fbdb3db2743d320519524244e7b35d3e0ee354444d0826644b9afcb4a2db32" },
                { "rm", "20348dca498ba03cdac2a9801928c5ee391c07d0a072a9260cc5a501cc64f1b7f34e7adc60f5301f36dd7fc2e0628f55bf3baf35464d0e0282c2f4d83d979ac5" },
                { "ro", "6b09564fdc25853e87c58ace864fbfaa2fad2509f8d6acbfae94c4fc7f804fb96f987139d131ce08463634a906cda7d40048bcffdd47f01550df88069346f1cf" },
                { "ru", "3e826d3f9d773637cc6d096e8b6852fa54133f89aa7c60eb890dfa29b654dedc60d27b13e555063daf63dcab66dd5b3b334890a0101025ae47ac4a3410a265e3" },
                { "sc", "0cb7ca2363fe37f6674f643866eb29bbdefa63d3d908bfad204ee3669f389409bcec9a52c534c41ce2e16f359ec1a410cd47ae99d1de68fe5ecc027878905883" },
                { "sco", "78f6328035f83623ddb90ef44d4a04de0464470910abb7a575919587c5956b7dfa4264a768787299bbfe16fa4e478da8657344ecae5ceed9613deb8d5dd2ff18" },
                { "si", "9046205bf1ad98123c0e55f9d88ac474c074b9d473159003f4334eb3a249656a3f8eca5b11b7d69f7d6016d23d252baca8317acb40a759be2b4a54943432b1c3" },
                { "sk", "bd8f9950c8617ce4330e57bc1bcb69fb714ff438c2a9789bc55085c0396db200b48071c8013b810c54795f8908e8da391d8c8c2f86ff862e7d507ecc18d5e92d" },
                { "sl", "92886f000ce671f0d1c976cdf6a9d6e7603bbb116536dc09f1e12feaccbc13280eaca3c7541512535060eb1fd1d2fb62310f87ed91186c53854301ec3c27a519" },
                { "son", "ac3bd68a0a90183fad5b429ba08eb03132f93585769fb727fef869571a1eefcceb91f401f16f95599e88b9e08fd774eb52693388698f821db56689d786662cac" },
                { "sq", "ed033af3dd78ef2e9f0fd64d75170bc4540442120635634a4623a7c1d5babe5e8235b7d2bcf7ce634cc38f3f46fdd11e1228756da629d37cb4dec956c366a066" },
                { "sr", "3820a6ab9da7703f0e849d99ce8eb6db86545469b767f7cc638a2ebd96e7d1f3888bd3a3b5f6fa3760c9285ca988af3a011ef6916205bb72ecc9c15b037602a2" },
                { "sv-SE", "a003b785654c8621081721e1e237d6c712bb4298329beaede074a735a7ab16b5681c2cc39704326cdbbe24fdaf76072f69ec39659ce021ee734d1de435234464" },
                { "szl", "4e0b45e606dcf3849eb312a95f4953aba8a1ffa00bc709c3c058513d056f3cd6b9bec0077b08c761c8d1ccf2411eae897f1559daf3060171b28aef7ed29ea0f1" },
                { "ta", "e969bfcb09cb75df2a196a2f67fec9ef47c9ebaf4bf33e6860603a5b66031f5ac6d9877d5a426712c6e03c184d228faf320e1a04b756527edf95405067be5b17" },
                { "te", "2b1f5d67d370e50a8c311bfa57468ab2ff020e4700b3a8407e714b9d9d3cd363d5c38bf89ab805800569e5a16f50947983a9a6a55aaeebfe132204774e916bd0" },
                { "tg", "6f4d8e5206cc46b28da42ff752a90736796d8a59ba46d893284a982e5b41b598ecf26a46093e8c0f40583bfb058feacf99ee0698cb4d96da5d0b4b3f4e4a0e6a" },
                { "th", "754157c39f38344064190f0fcf3b0f4a2789719edd57f61ce4f4714ffc19a50f00c1cdaf383a9ee3a14f333e34031251a9fe32b8e73b71f8dba2ec70d7cdf9fc" },
                { "tl", "4c40c22eac9ed4cf39ace4efb52bbc0010a6e411e2157e143f6917938a86bf57cb38bcd0a61ecaf7fd8aa227265a3f384acc7f8aea79d1d73b0f3a3c571b3d2b" },
                { "tr", "ac3aea5083f76362a2758c7a7d43efa4a0bc1f3d8d421d9517fa88629bd5398ec9a54f5ad726039baf73d80400cf34a486b0b007b2f383fd7f86cb4fa0e7e2bd" },
                { "trs", "c6bc8dc1d0980547c2507c3f2fbbbda4db12b899bbdc10c7ec6eb5386f1216000ec2c2cf543ce74966ed1ade7b007ed5a7db2c22c47fc15686aee548023529cd" },
                { "uk", "27cd27aa606f6fcb72c8d2dd8c11056a165200735648321d5fcc15e53c1d5cda6ca3ebae51000210e0175986bd177550d7060a49e0766161e459df2498c189dd" },
                { "ur", "baa5d626945d8b2757502ff1a7e9ed4ef6b5ddc284b81860d0cfa9cbb54ae83c6d370f5940191132ca0d0a281151f1e46ff6233f956c5adcada6698bae568438" },
                { "uz", "5a0ccebe813e056fba3be16a7724ef95a873fef5577743c5295eca9bf751f9e42e8364442879ec0aefdf9c9e80c30021823bbcbd9494294be6de90e2e88112a8" },
                { "vi", "f51c7fabcfe55ee5af8561de458f68cc9541fbc7bd33c3381debdb535ae5ebb922aca695fc0742d354fb3e4d8a4c79bf7f70dc20c86ac7bf8052dbaa3d1d4087" },
                { "xh", "76de541b975fba7b93cfd9e5062c361e7260fc5260dbbfc6e7094194abc7696fd72a85d64510243179c2e9d37343536c27c399d65a85b29dc5a3121ec5b74ed3" },
                { "zh-CN", "dcab5dbc2133d9348d82fce4cfed6942967f092e7ed9a5697f20041666255524a6603a5343b3ae1a40a210a6d071e0f3a17c176b43219dac85ac5233aa87c9d6" },
                { "zh-TW", "a95456dfd260e385edf3d51eb13208d048235e1a852281e4ec74387dc142398e5e6bde3f9bb250776d738b0c9e08501aab6513385e6c2d5940d13c0dfd0ff0f4" }
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
            const string knownVersion = "116.0";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return new string[] { "firefox", "firefox-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            try
            {
                var task = client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                response = null;
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
                return null;
            }
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
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha512SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
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
            logger.Info("Searcing for newer version of Firefox...");
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
                // failure occurred
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
        /// language code for the Firefox ESR version
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
