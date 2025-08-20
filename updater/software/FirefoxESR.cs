/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.14.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.14.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ef520750b876a7d43aeabcabaebf764fc2c28b602e289f86991ecea67d96da988db915df716b770bc0316a00e0f185861f337bc48697d9057a38c2e5e679fb65" },
                { "af", "bc1d02b2b0d904c99b7a7f36bca0a8cb44a6be355e09e8b00871aa00c4c02c220d16f95cea89311f242a4368ebf8deeaefe538ac963889c82ebef01bd5a3324b" },
                { "an", "ccd4d8aa620bb14194e1fef9aa69292f1dd426541b327322b0ee57f267c064fb73247bbcc89584053d65a239f06a2b9d3df594bf64b621e99585cfa0fdc385e5" },
                { "ar", "5d412e8b6a53f06c39f8f5db865577f633b5a9172c44ccae2596551cca4de1dd764ffbddc1864dbfb13a582ecd4fc19ca788c1aa1bff33975faa90b96303ba8d" },
                { "ast", "de7dffa13d60189ffa0a609a115decad7ca1b2eda00787c3322aa75700094d263f792683303cfd539e657b88b5c836d7c83de3cffa8e3941a7919658e147393c" },
                { "az", "610a8a4d3b9ab6919c1a8078ae799f526d51c8d2a000342927266af3be531b2f72b54f831fe44714067f3d95b93b13cabee5b222c0f7575b8c93fec6446aaba1" },
                { "be", "222a56774b0665ea621d40d98a76c6446f0cba739fe2033d7a4cac5ccf2209f259797fda0603503da81b31fcc2c503f40c5e54eaa647f78d0390f8953f880ba7" },
                { "bg", "a2ef8ee79c8ccf3cb39710eca7db1d3fae5144fbe5a04cbc5548d8108bccac641b33009cd46bfee3c88477e76ad175dc2e42971c46197e29ae6114a034747ed5" },
                { "bn", "f3135f49b8e4ab265654a9181b4367206e6098356d7c3f8821c0d2df08a3ec9276624dc80a592c954e15f88c85d0c44fc191759c64df31c7ae0da29267d94c0c" },
                { "br", "210a5b361fb67c395569848b267266ff6261b9adc53d25a2776597932242b12d0e8f6cd67d139a89ce3077df16b74378ca19f7fd3768ef9c72714fa0bc1c1a00" },
                { "bs", "8d723e3f7f2d59141ebfaa13e8a397677634a00fbe330836c753a6fc85073297c196af65d6f882134d4514ac86b18cfcd57cf2db387f1b88d5bab1d61012afd3" },
                { "ca", "4f0c861a5b4f67632cecac70c988f42d18ea67c4ff619d007cb4e3f27626aa8f058df0fcbf29a1f49196dee83606cd63b3f3d792262b038df2f9a06eed4bc64a" },
                { "cak", "90379d91e602e682372e8d6eb250ca75da5cb66b7a7dcbd4dad86ba504ff5dc7e8547676e154c4bf06369c44a2d72112de70f782384117da8bc07973b896e3fa" },
                { "cs", "d83eecfc29af8a17c2fc31665ba0f6663d42b09148273a370ed78564f307aebb015c8ba42d72d28462c29e76a4224c50951eea3cbd57145ae04a7a1f35773b0c" },
                { "cy", "ab6bf79ecc2a17ff7ff3b47e58e659b8406c48eaa2c562722090b0f9b11766d49e1845f92b6dbd70943113ae09d8306fb1d12b846529a805eb32742b58c191ee" },
                { "da", "baed63853b3da9bf7f7b481534bbf1d8b87370c6ffe9e65a518e9c5a0f172f2ba29f9360c6f3fbd109f55ce8badeb4ec5018986a0711db0b1742f1ab786df400" },
                { "de", "0d58d72451e7d9c13936cb0fec54442fc2c2e7ca03b56c864a79df961dd1c1d2f372343eab455e0658b1cfaa0fd16f8789eb5eddb9f4c0545606c26eb47d6e38" },
                { "dsb", "1f9e41b548f4e7b740ef1ac935d2fc16263a08e6369af72781548c218789cac36d0bd9ddeece9af297a23594d2532cf19ee2f02ec4049e7374e2c3e75db0da3c" },
                { "el", "dca8cc523b8a10dcf0298812faa8e8d488c7e250ccf1b633cb32d11491c254169abc925867985ad42afe465d88157898a58f8c6ce8fce447570d02122776915d" },
                { "en-CA", "1719d60deec7a6040b271a6a596aa89bb7c0362d03a3fc82afea76b36b285a0babff1f9d123f6aad872ffcebab0a0c6b30f489cc43ef7b2c03f36137c468311b" },
                { "en-GB", "4cc1fb7c5fdd3a379b93a18e3d9dde63d2a6bdbc15c6851068aaa576c1770e983a8ed48737b814bee714ca547bbc7984c83e837a03d42ca40f8fc3a7febc8f95" },
                { "en-US", "6821416826a311e6e5052405a1fd15e68df2cfa33ec08f99512effd3f9d8a3447c92749e30d26b13bfdf1b52e421722ac0a0d834164f6e081f8797340ef9d1ba" },
                { "eo", "d8aa28e419a254e0791c8264f127ea3fdb0f01dbe3bd63f4e6eeadc7f71e93ca96c1c87a1508f6e550af756c068f17290682eda52ae555e475e07d4ae916d20b" },
                { "es-AR", "baf5ecdf587e617009c7c6237cacea5a8ff4e92696da27091824abb7d5076f1c71c260b4e971966d80d7f5a65d886fad25fc6d50e681ef7afd25a303ce80afca" },
                { "es-CL", "45776e2362b83a8c19535d652f44a39fd3696879d85b814a2c26d7a9c0a7538bd10e4b868761d4eb73f049a4c184ddd690612a657e825c377c1e651625a9c0f9" },
                { "es-ES", "ca2b2aeef021c798edb4c831c47591e90d7e55240b9f2038bf4d1754103e197dc33471caac485500c731b07d41096a1439ad26cda263093c93d92a378acad855" },
                { "es-MX", "ecaf948f21292c48bae0b17372f5757488571bc52a81b164da50a84ba6b50441cd2857e58b04b02214b51e2de245d9be72858078c0032735e1dbbc4530e1758e" },
                { "et", "a700f58b051744de7a553ab4c0408958ff2103c762241ad2f574ece3ca8a17f766f865faf80a0861d3c07fb1589de5cd2a76d32626c537fac49d4fef828cc684" },
                { "eu", "4d627d36c9521133b9643b53fbd436ac58264cfa5c26e379db6ea72108d859c7d1cdc1508782a40e252ee423b9194ea2f9ebea9161b56b6ac09200c36cb6eb94" },
                { "fa", "d75be1f1612d52e4ff9774cfb88970de60ab69ae6cae31c9276b19f8f3305eb9ffbfbf0d0ccb3cea5b2ede6ab1cac93fa64c7f7b328d768d21ff6f662bd76993" },
                { "ff", "d80d9b115437149db23d12ad63188225d3095fb74a6a777aa43b31111088aaf1d21d4cda47c9f4cbd62a0883789a08f7f58add2fee9bf053d5988c0ca931005f" },
                { "fi", "d1f0b3c4f2b776d27309f8d97cdbba43fa8a39de1b5dcfe25f63c5cdb60086684c9c5b006e17e34a4d7001888e168d9ad357cfd4c52ced4079d1e251c8ba6c9a" },
                { "fr", "2c6917761bba68ffe11baa12076b79995b08d24cc75ab8a9d202de494c9afcc39f43b64260d6551fdbfa0e613d95e5d05835ac9cf209515171e28759e4ee4d4d" },
                { "fur", "23d1f6215ad46e74d32f896da3a5444a2f3c2b6ceeba8beb07a30034da07b00fd05495a40a855b9f608ee4e65c959a7b7c668d8f12e780a02bd487b89c356ac7" },
                { "fy-NL", "da6fd3c64ae815f2f42deec211d5a759700a90420e866e0d02372a5db9b9e61e8140200145e0e28450308ff329742ef293d9ce9a96b84406be442d4a43b7fd47" },
                { "ga-IE", "fdcaf27e9173690d55df5776cd6b7272072399080e1c9001a70d41f2dc6a2cb4316d0b1301a501ae353b2ec45599c0ff03518508495b41af6b55506b99a58f95" },
                { "gd", "1b583ccbbffacd8e2582784be358116d270300d26a6c633afc3f7a0dc85351d7529487aaa17b4b441d1e505b9640ab5f040b18fde8b0e2e858595d1f13fd4b68" },
                { "gl", "524ea519693c68510428ed99f189e8bfaa9c76ca5d847d0fa2e164bacf1ac88e52218bdac8c575dd3f30dc5a6bf4cd31f4e30326053abbf600ad30653f0f3a1e" },
                { "gn", "390f1804b9dbee6598e5320e8a5bacd2fe4aebdf02a2c7f4705aa4736ce2247fb5ae670a6384d7006abdac0f386cfa2ff22dd754f0b497f244fc5fd408b9a4ed" },
                { "gu-IN", "26f87337b1e02372d9085f809f8e49b97ff41e996716e984bba7e11debca6d5381dca19651136532872e4cb83cb9e8ccab80895cc338a3c33efdf0146a004b69" },
                { "he", "29a899d7fa9de0e1081cb5908cd362cd7b61f1329a34ff422fb59af1018cce633be2324c0d1acc0b9afad88c70a03590fe2128e22334a99f98fb7a4a15377b41" },
                { "hi-IN", "24f94451e9b28c54b1ecded1ddd18d444b44cf2571d61cffba0d123d9ab58eb0d25ba15ee2463376004ee9e4646799b4fad6f7f198d1042ba9c38ded118e533f" },
                { "hr", "595357ea90d4740140bf2b88799c89eb08fa91eb29684a6acde2599674671786dfaa8e88d288362ea8c7274729ae7823722e77dd42c039225d42f99ee1e2d1d2" },
                { "hsb", "5b86a3eda3a3848cd8bd30cdb287028a97649f05e607475e777adbe0cc968ad54e064e95fc340ee5d412f6dbc70d10de3f6d05fc67a42da0a747450e069d5ed5" },
                { "hu", "a9f7c6cece552fb9d38d3186c17507e15f0ab5a8f3edcd776326a7102f88ceb2d9890da6a07751813b2dc16997bb3ec42dcd3d75657a1aab337792fc1adb2ed2" },
                { "hy-AM", "b57c93a2663aaaae1fb3d541d99e24cad8f1d2eb8fd677220cf75b53e6f0d5133e42dec714467c5ae02dbfd83f8bf05d8e6dff75ab4dc6728549efe238ad2a88" },
                { "ia", "7afde03edd854a7f8fbc2aa8b5ba0d8d71b99ff5a7b8ae9ad11fc231f7655b22bc2b6cd57f837394ce7380cdf851f9dbe137063aad5255cf0f1b3e56b15b5e6a" },
                { "id", "57d833bcad9fbf68fd9b95bd127f25ce92215d4713f5d29bd13754e15f36b845dd7a3160d8140044106b87253083d182f55793da6530a94c3327aec7b2203da4" },
                { "is", "b83eab6d6f3a3af7be92c97b47c994bbdb3340be8e616400cb52c119238897ed1b93923f433162730fb12951aec09323b3aee98a76293711a42d4bc1276c2990" },
                { "it", "86bbe2ff12b8348408f8de73d1f70e69a0eab97dc80549756f4725aaeb54746890883f4f4cfa17a29a1762a47dc08ae327c3a3a8e088da19fe71eb8e6cba8f4f" },
                { "ja", "1e1717ac055a223dba273fa5462cec07defc64a27a5a10e83d0d9f8d05420388d5db54c82ad1d927e75173dd5a60498d6f8b3fa70edcdb01a093ff3ec6be7853" },
                { "ka", "0414844e4f9f2ab25d117e96d59392b12a5455127141a27d9205685534ce289a2e2174595219f658c89f99f04594e05efb37c59d229cbfd6dbeaa6a47e212bc9" },
                { "kab", "32be0c715bf9000a36fa030c3d21a321e45dc6184841287b7ed20592999e1215bd793556c7f2cd8614f94b2866a5cfca305ec612a03f4c101f8b13e96ab44969" },
                { "kk", "2e2eac2b51bc80b943e726580c89562b7340c3db38c0bb50888577b92f603d263d05a7bd0230713476890333648e0ffd4314b1887a18e515a2f9add7dfc88a55" },
                { "km", "d21eb700a46902c4dd150261056b669b03e4cf97cf3642abeeb15330f41f9fe62faf7e38be548fcfccbb49133a83525b0529f61bdfe2cf72457c1425b90a6ced" },
                { "kn", "ffe7f137c94298f95202fe0ebba6a7502ea6b47a4bb5b99945e8f6675a8664b54232aba8a6f278e2860828d9b221d6f23bf790f6ddac01167631ab55eb0a2946" },
                { "ko", "7e86ef79bbbdd09e66d89e3b47f22d54b33a916b4e0fe01579c9fbca378ba718cdd907a47ef878e00417e004539be6299f11f864848bbc65ccfc40249fcc7232" },
                { "lij", "162ef4ff5d7d2d8292f2baa1dbceedaabe95a1a745535476f08550271ae3f23e651507ed1ae75b2af5f848f00f5a4882aff677a01b522e44012537d5674bb10e" },
                { "lt", "7bef32a057952b425f18cebcea4aa84a892c5740c066065a843b7073893afaa4a1e1272258b113c01cdd7c222a2c4644ca4e7d8c7b4f3d1df8e21cde1b95b453" },
                { "lv", "5409cdc375ff48382edf2be0ba7f41bf63a6e0e32d8e76017faaeca62eac3adb36ba8999a079cdd1087c2783e749164b51f46b8f0a951e19dfe810a9e1185f0e" },
                { "mk", "7f780d6d8c2bbe3139e44aa011c4a1e11e46be0db0ac7248c958391fc49327a8f369f1a5c25f5dfc5040c035617f0ff18b47af422a1ca3cb64cbd7d53308e670" },
                { "mr", "9189012bd0731af4ec9d1fa11dee541d6afde4240cb1e23e4411a5330aaf404f9435b3e9921c03d3be964cb44b4860c2bb0cf3bf541f978305fbd1e3895ca170" },
                { "ms", "f4ce8254656cbb3a7b1705fc60ad62c2c6f87f08f87774d29395ce211e2dd3bd15443d362eed66d2b0b7115463d7ccb12c4342d2b696408d8345f8c4befc9043" },
                { "my", "3ac14b6a81e220309a376470fd9b30e523c3fff094a5ed5ea3e3b03749d59d2b2f2275bfcd3c8f6f3bd081afb4c0d5f0a6939cca414bab12bf2ff58561855db6" },
                { "nb-NO", "d84f08eceaae6dd5fcebd95bf5c5e824bff636b95dd5018fc6798da57b5c9c59e1e5ed720df6e540724b38f0d84e1040a6a0147cc0ce503dd14949818f38c8e7" },
                { "ne-NP", "4d7f09ef9f8b100a02011d0a2715308d7888794cc3579be49e34f64c2b8743adf87b55ec8db3eb4a7fcca5d4fa966389b9cf25f602e2f2ad1de6d62bf4add9ae" },
                { "nl", "1a36b477bebf47ec566d1a02406a85ecd1f82bf65c256cc318476d7bc7cbd2ecf31046caed4cf36c542fa5fcc2d6a3b0e85a9735a5c27400bcd03176563e1c95" },
                { "nn-NO", "3bdac9281a945f0e95b34d49c3fa440a2da247796343ae564f0d2af0066e2f428491b6320c0f2b9ae214ac1c4a1ae70e01df3dc722301180b51281e2eb0f2ddf" },
                { "oc", "2ff1c53dc8399abf22842dacfe9f25aa7c11e6075618ff0a0ec20c6153955a20c116e4d11e3ebba96a3e1d8981a4320fe1cdb421f6d268a1367e5d67a7848c9a" },
                { "pa-IN", "c25d67c9951ff9688d52268f031daa8c39126e5187f29dc7e3ccd4e6a5d34f85b3aa4f0e21cde5a0f702d49771623b364cc6b37a4a2b4069d876e17239456ae0" },
                { "pl", "03ff14ed8bc01fac5f10369bd467dd759a96a41fc586fe89c17a8ae7909b93c1646b6be4f18f02905d8e2299842afcf8d2f6014935919b5c7803523ce42f9a57" },
                { "pt-BR", "fd39667961b847832a373e036c2f991e61abe584dfcb85742cff834ede09c512fbd3f8eb2c600d30f4c22c3260e6fcc9ba7b3c486ba873409e0db8e9a91a8d1b" },
                { "pt-PT", "304bfff2a4061fba757eaf9b1463e39280e2998c4166f991a7e5ded40fc273bcbe20abe6983742bde6821cc8a7733c811f9e082afa7effe85e66429dd468e462" },
                { "rm", "cdf83b7ab7e21991b58002d8d6119c8b769a88e7614590981341c9e7deab859d04143f430ecb20e0dd05fffe131b6b312c5df11b63eb9ee7feea5d34bd411636" },
                { "ro", "fc5491f23bd48713d3f9a4b385625a007dd87183662483e6341b6b90fb6996f4baf862468a83c02289e5c76e707676d6bf60214ccbd7e29208d44d40133327ca" },
                { "ru", "c81286411ec6b4bd293d84f2df250f2e70e01b60706c54beef6353d50c6f4a2bd9c2e8e84463348677deea7fe6097d9b2ad427cb5b533eb07d53590c642c29f2" },
                { "sat", "5ade8d1579f082c32bc7db3e8275fbef8f574eb6c53861c542b28d68126b6d46af8400a95d318e11d81d7ab765603d7b5fcf9b1ee123d995f41a3c03cdf35be2" },
                { "sc", "70a3806fa183193224d861aabecf7886a4540966db18defc8813368032e28c7d90ebf7fa81f2e2f8c8fcebfc0351379d3f522d7fba6567ad518105a10c91c87f" },
                { "sco", "612668f9107d81e9691dbf7fc5afc86c7cca2e1222aaa9b79b0306a367bb40222b83ccdae72eda08b95acf1bf65b20f9458200ca7212080520f416304404f798" },
                { "si", "cedbc2c3079dade03d58594e63f43dc524e725f93d0899505d046bd1ce4de8ac2bcf40a880e97cb2bd6d7511d8e546bf2fdff37bb3ca964d9efa41d7a5dcfc5c" },
                { "sk", "0f6ae4a6cfc319207e89075845866c455b9151aa9cbeca5c9e64184e9f17bb18e35dd5768e90e3073182faf8e4399dc2a1a42562fcce98d90224a63a34152192" },
                { "skr", "8d16cf2e5ddc0f8e356486d1da966d1b897303486f76810c192f3ca998e870131a4e989759214d15a1df1bb78b2a1d0ffda7137ef00dccdd860d824e726d6369" },
                { "sl", "ac366fba56f7bbf0508acbf99a1e1e7c90aa7981ed5196ef408f89427f310d14683fe3b97ea3a3872ba84ba6175709adba8df45055b4bd5a1373bead108ee323" },
                { "son", "f6ed4406a8348e30b168f0b55aaebfd90e01d75cf169900ab856b7bcf5e7aa1be63869623948295751fabc113cddb7f7498b630c6dc3fafa673c4207ac6af106" },
                { "sq", "fb7f9d07b5b92b0d6ffc922266f3a527c75042c9b98587df68892c10917156ca484c2b924242abf2fc58ad86af3d6c8c08bc5ef87088dff2652f6e11d8f89df8" },
                { "sr", "488593dcfcfa4b64e25cb965dc280f01cdb7ca7003dbcd6ccfe9d0f5bec2034f75bb9d0ada34ffd98a44fab3ec19825e637ed1db82a7e26b81f0749cc94403c3" },
                { "sv-SE", "ef595f5dc9996aaf8957044215f6eb11efac18cf0cae61a578aed654446c8d5246072d1dc1264d9c556ea54e8c6d42fdab5d442c2ea5ef1096195aeb88988dfb" },
                { "szl", "615f4272d62e38d6ba0fe34c4895f422ae7ceca206a072cda02e726f624262c47402437e9946ee8f93c6c8263699e830bfcf2744d56e62bc656f9b63af7db243" },
                { "ta", "aecf8e66819786f87e8c541e67d85fdfdf1b97dc6f3b24ddfffd7560ee6de3621d2aa23fb759a0781d8ed48e0cad961f7cf7847afd7369c8790cd469c5185b27" },
                { "te", "1f21aceadf3ac337e81edcaf8e582a45ea76736c0a3481fdd6d22b2d25c3eb3758c13011c9866287efa19171c196c15e04dcb39328f5fba96842e36ddfa77b69" },
                { "tg", "c1ccc15e47bb61871f0dff8e461c5cb8c9ba741fe80f0392fc86d47fae0148adcbc9276dcaf33236b2f52b6f6d9e7db07df2d708c5be4c0628c968e9663141fd" },
                { "th", "b649187b8a64e3100d83eea3e03d490da5ca1212b093247d098ebbdb46b62de682a3a220c476e947c048b38c22f73064d455fe7335dc5a57287cc3695b13a0d2" },
                { "tl", "56df47683b5b91f63129da01ffb10bf04e47184bbb79ca34a4d343ef52f132cdb970b4a49fa285d0336c903f9d6252be7a0d46c7b1857e16ea926f8d7ca5c05b" },
                { "tr", "8febf761605e12f3b7384f177177dfda9fc6200a128c484148ed347e9e83c9a6321859808d62ad00e790bfddb9483a5a15e6797dd531f20a08d53a9b409e18c6" },
                { "trs", "fab0493fd84e55349a9c4acd36184857a297761dc16476dc7b7eeb228a0226d7ab99d0fe2b428eb91589e1caa62c94df191b9e2b2c26078fbe49f0971c81a52f" },
                { "uk", "9b8e19602bb65abed80de22bd3a6a0000c98fb701b25a4bfe73eaa96c4917e83b97876a9377b27b689f29b0456cb38a7b5b146416adacb64b07ee7b727a30f61" },
                { "ur", "c7273e8b25025013ccb046c19c82ac9d13155891b0bfcb048298ee87d17b4d572053ef31882829d7c18ac76b9942f29f756acd7b1104d368c5b6fe9f724a127c" },
                { "uz", "fa525ac316901ecc900ca59d4694666211188a030477003012e320a2ec9591358bc8482efce9f73ca363e00853ebd4679f09febaf1338df619215c58f57cb714" },
                { "vi", "56af999f5d670948c08857732978e312a3b73eda0a4c7a1f8ba81070169786fbb23e403e88642a0f49a98bc312c42a134bbbfc4f7a40447dceaae180472e12ec" },
                { "xh", "e24751f932ed38ef7b4d185c3996c26b8604be1eaa10c1063fe42f1c98896f6871739f518eb4400c1efc0378da145b3f14e6a4e40b148082f44070bebe470ad2" },
                { "zh-CN", "72b79710bfb681f05b2f4100cee6aff62b906d9d742bb44871b0612114aaa4be5e778957d5b7ce1dfd17fcee5f42f21be7d82c47562c2a37ee15c73a2c1f469f" },
                { "zh-TW", "fb166303db2759e3d1c249fcca9a39b80b3103c9baee565f93850c02f2a1995819e2ee77f73d538230b6d943e73b9c316fefff218bd6f97d3b0db55e50cef20b" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.14.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "3cc99799ade4d63bf36de150985936ac8c099557d8c46dd3c39fd463ad4529a4b012797fecf0f9e503634a4f02ab7d2cf8fe31b4310f71d8f176229f261d16cd" },
                { "af", "24070ddb1fb871720975e8065e04a95356c2d68b56110f4c3fb15833138039e21a8d07bf1e3d906a855393d8b9182852b212c7c6ad4e7e5bde6f8f4ba1a9da51" },
                { "an", "36a203a8afacac9a0cee3463e5f76dc457159436607f3a61f2eb8532db9bce184526b40cd6ea1c163ef29d06c1eee35a378bbd19da7733c0e56bbe6e55391550" },
                { "ar", "da5483ab2694b29ff1143b8fc2bde30b38df63ce138d121bbcc22bac1fe57485cbf105d2b44a3992d7ca4e437035406cf105fe4a4c9ac5390ae9ec82c6b45c87" },
                { "ast", "2c99be1ae535fe61c4acd67c5315d1e99f249d5536365f29ae83183ab6c32cb361aee339151b1aa9d45f83fb8fe468866e199f7ae3caae9c542ae55cf29b4b9b" },
                { "az", "fb9df3995c123cab8f27ceb3dd22b71213a5f5a7e9b42a8ad5bf47c7527f3bb09ec1e197caa0011f7e59f72bb4360a6c1fa77dc7e6b2f0f690bf3049ed7e7c2f" },
                { "be", "a9e50f0b4c33af8c56b96f6df3ec233a01e63769d8db5ba7c43368bba6978ea4e02bcd5d74f5114bfeda0f27f0ffe5df30c23dbb5d62cc93a400d2c43d2742e2" },
                { "bg", "d03c9cf626fbbf11db9b122139aa56d18c058dae0015b87b9f5957db93daa3a8d6674cf324f770da456695a08975f0edf7e8118477f195b207be09675626e52c" },
                { "bn", "656d280f409c3eef101454ccc78b5bc0f12dab5a22b0ba71e7c7d79b4014ec7ea73c0fe7790253fc0715d9b6be891418d10a9209e62b6ab40d15d8d3e6bab8e1" },
                { "br", "9925b8ad86444213f809a3076f4b6b999b0b706d52750bb6420aa68dac4119f8a094f8b7a09bfba71787490c7d6c74976b364565f934f81afc3604a370e83906" },
                { "bs", "8fa476a9ebb7c6226e1101672981b6f16d77a984b1a3a5d7ced411f70970e8c6ee163759bd4e20ebb91b9b03ed13c54a2137f83ab39e9fca6e4cece0c267466a" },
                { "ca", "a5407a9a46c2c2f6c7b055fdb2f17d098a46ca5f9eb4f58b896dea6283d70c846a3489ebd8c5f93f33b91806773a00c526acedcb1d411d5abe0a3e27693ff2e9" },
                { "cak", "111ccad5835ceb53a900af9954f6951ca603f8f7c0d78dd6d317a5c98f0be509d8ad79d1d8ffe4f656247dbb3de95e2c7a9df617d9c0e2f08c244c98bdc3522d" },
                { "cs", "be029d30f8af76ab868fe0979c0a6d67d9caffe688b6b2dde9f89a2f627a3f51ecae87c734567b9710993b8d55151ac2f4af81d58feb91dee0caaa2a372a34e0" },
                { "cy", "1c810114d7125a987ee8add951c69a318bc356bf598f876ba499e6a9301abb85b1305d18aa3603734e56b5d932c22d530c54bb0e53b794a6fd5e1bc9f94e97b8" },
                { "da", "3b01a2e9637ea06258dfdec32b0cb7248697562d04aebf033b15142a1c860792c4c5fcb9848856386b6688d9ef061c4859c4da73b8e692dfcae0550d147e67a6" },
                { "de", "91cb481c2aa66e53896199aa405deb4530b7bc7b37a8c6b1357061bd41d9508e4996859828a2962433117146ad75ef466493cc1a5f3ff28c8e9d818d2813ca89" },
                { "dsb", "474d5a3f894e7e7935f68bc331a92c6f9537fb1e13a6c72c7cc0c3234c395d89090dbc0c73db5f2b33f51b6fd2d94f4b3a9db40d31cfbe832fb8218c7d53fca2" },
                { "el", "fe5ce8f9669e14d7a62546327f8b3a87da9c5dff447a38e7cee2bcef5b372eb341125e1cf70e2b9e3de695ef689d83907a7ad32c924986df4e2aa9174cfa9356" },
                { "en-CA", "c532abd41ffd6f9039e072eb6a7b42fcd0b7582c6b18f0dfa39616c58fa4227c0b0a4857d5ed899f9cf684a4276ff49649331ecf5025d6be53e138718a6897e9" },
                { "en-GB", "2b57daaccac2ef8d90e5ada5f9e0e476f64575858fb04f822a343d3034b9d3b74bd9140f7f59050aca8747923fd14aab334c528228a28d96166b380c0a8445ef" },
                { "en-US", "10c4ff1c87f7825dea9bace25464d3cc741396ff1f717909febc5c0fd41608f1e69be38c7cb04aab2c33c1c5945e5b271c841d6b0060ddac0404cdf6c33b293d" },
                { "eo", "f682c824ac946c33ec3104cf2ce280af40ba4c2bfb5a01456912b5567902ecb5613e66a06720dd903b621969ff98564985d4640fdcb9947e6124a8187cf21a16" },
                { "es-AR", "de7c91a1a50ddf3db6ce4d69f1cca03a77475d0f3338544602660b947d1269080134af1e5408aff28a8a185b5a0eb1712eae8eb5998f22082ad61d1dfbdfa921" },
                { "es-CL", "846b55b741cf5b918f76661a7a1dfa9f88e498257441fc9731ee6b473a4f6801297130c7acfd6097988542943c5561577e628824106a76bcecf038c2b28b9c65" },
                { "es-ES", "acba1c99489315a0b098497a91a5a250e6aae4007e09f550ee42967030aaad6c113449a8419d39d83d45a29e8a58697c382f04ea754e2454ec5f7bd2fd7ebbe2" },
                { "es-MX", "7edc1736a997bd42db0624847258882fe76ffed9d247ca0157226f399ec4760eda3988f38c650e8583af7f91589c065ffdb10f1c422dca1d1c7227edfea3a238" },
                { "et", "400b60a4b8aa64937a539a7ce8bb961416320389b1c52df42d7461ebb30ac8e403dfa92a655e7b4b4d5f9e6610ab6bebac65ba1c2a39e94ac026c11660ca8781" },
                { "eu", "47e7ff521e0f169d127f949625388bac1e5a0b80626271af857fd6238b0c4d9b1f1b5ff65931df36fd69638ad67ec44b346befbfdebf471e0aa9d2fe55abb188" },
                { "fa", "9830723d289d92da77e8bfbfd056a0965767fa3312fccd6001507f4a5a458bdd033955785b0470fa363639e263789caa8429b97237bd34e0b124b20a032e9ca4" },
                { "ff", "eb85ea5a4994db218c6c130c89ba68259defcf03743e2d79e98037dbc15a355635adcb2c79b32198cd86c2880dca2d121945bd82144193e34adaac28be77e51b" },
                { "fi", "fc37dab6491aa3d5031cfffbeefe15c286ca44f2d8749486b72a76990b96ab6ef66252cb43e25f1fdca44b81cb82f98f758b21dec4bfbd5a36eef971847f26c9" },
                { "fr", "a89feda7ce8afff079c4ab2f4c2106bc60b3bb6fcf1dffbaa017b47927a69febeaf89a1cda368ae909d5e849d5169e587ebdb4dfdb7f069d03ac5c980569087f" },
                { "fur", "3af510a2381f0a880513ac1560a301ccdaf4d92c97b10b043506cfc9ca76f1dd48ca79998156b466d7491215eda0bbabc8f1165722ec7c64161759b1f37e71f9" },
                { "fy-NL", "86f26283f3217d7ceebca8a5b179e68eb798491cc5c57b205c91e0e56adcaee5c351e9b7687d9943bd717d77399de94e289842b7ef137364b87d411111bdd389" },
                { "ga-IE", "63c1f5eeaa9b42cadde708366f5422bd7dd46fcd647052ad448e3c47c843efb351df09c9516d6978a4b949f2a8e0dc4eb35aae4a34f2094a3a392557ee8ce9bc" },
                { "gd", "e63899c2ad776dd1a281bea2b2a51843823753afc2e5a42dfee52dd74a7b210f415fbe71af63516ecea76ff3bcd58b06d7893c9372a7f9776558ad7d84be8a1c" },
                { "gl", "3b5afaafbbc089582e096518e106b086cb5895c0e3273d2c085f2d8f830a6066abcedc26307359a70e5a41aafa7e3d54368f23aa0a85d0f4eff4124ae02a1335" },
                { "gn", "31160f3bfcf3677b76866636b002f98040e8283d1624c9277b4291fc796abd4168cdd1420c6da56576413b2cac46b8873e9621a219647ec982cce4b0a680bf26" },
                { "gu-IN", "5a2e7ea69026fb6a4a592f9f51ad33e69267d8d2706d03dd4c213ad68b1fa4aee9f1952d93cc64b599ed50be7cc652b218412622b2a8f82867a2f089c0da0a4c" },
                { "he", "4bdaee5fd9c529b6ecf9eadfd2ee30860c3e125eabc3a1b81a34a301eaeadcfd20b8de5ac6a76e5861b091691baf10ee10986bb0c33a19b1b7e90c5ce2c6d2a5" },
                { "hi-IN", "80436f359fa3292eb22aa8745ccd30c0a05095d73e77abf48bb5f2e741a7011b38fd07c6a21254944ba1a78f77e0bd5d96d11018e7f767626c2ac74c1ee3bb41" },
                { "hr", "74e586cd63154cc079a6c79e592610e1eb0f67b066caaf55ba3d01737530c4804cc618a4cc4a5d7fb1636bc0d22f5c39c33b32eaa154f67446ee2e1385e58748" },
                { "hsb", "4299628dcd1d5a277b6f56cb202386b685afe8eecb6476ba3378d399365f7a1cff5d19759ae1c4d8af5ebacb3046ae0d4665bf4c5e83a3c73a444b9182d2ec58" },
                { "hu", "14960c9857cbcc388df04dc929e222de8cc2987b6a61ce4ea285c3dc30894f2d795c2decda1c0923242bdba848b4389cd4e2396b93d2b82e7376aecd00bb2743" },
                { "hy-AM", "47f65de68b0951616dd3dbd159ba36c053505fbabbe25de00dd29cf80d190d8b3a2755c734d3b33e3da694114f3d950b53fea690795e6e0001e6d2b022376c40" },
                { "ia", "f3c3455ed805d9bea5642b6d688981df94a52b365161836493998e3a05623572fff052ba419096f285da9f5baaa6350d58e2d85e562725e682dbc23a60a7d178" },
                { "id", "8e79c2f9b27ffc2de801a05e2155aab1bf8a49efb05d456784de234652608576c7a4a59ed29595b1facf0e8bfff0b3157ed8ad1b12c0b960ed552387b6df657f" },
                { "is", "2e64e63e3f13a98aba3fda2a2c2686481c9198bf3dc060341a12230e3c456423968d8a89684ded586071f70bcd7c2cef2f9d88ef1892944fd9553b22920755a5" },
                { "it", "567ce485387026428e2fd4540356ac0de42785e70369923646489dc70dc806c84f025614914a231fc0e7328d5618124504db2ddbcc673a0d8b70d3030843e836" },
                { "ja", "6189fc13296e86e66fe17dcc91fb30e573bf103c4c9270f55f2ca82acc461077da53e699f0b0805bbbe6d4824ea4b0011e30595e36a412ea9788255d24e10fcb" },
                { "ka", "6c80574e56fcaf29d225cc1a2d62623554b8381aefe8719877dd6a402acbb01643dfeafa9e7db8dc636fb8a335c9f510ba52e420140b1103e5ac93e0da1e1904" },
                { "kab", "208d0e6429b286afe396541188eb4776a63028133029f878e1373955e207fad67def85fa4d0b315b813d9c7b833eba47a4d4aae878e29995c595052bde4e2f38" },
                { "kk", "d33ba4389a4bd1d64d3dd27a91db1ab8307f1c0a6395c2abd432b3675659087c7d9f231dbafe8c133510861403895d051c4f620ee73deda76503d9c55cc927ea" },
                { "km", "114e3568ec08e40be0fb53f5df9b88f953fcd85a0e5b9867eb5382836042623e9c48861d6d7e8f3cbb0a7c9d3ac2fb5ce9deb8e6b1913c6b1f899a4a2ebab81d" },
                { "kn", "d93195396e9419927176f14b086f3a6a87f69a09094b63ae3c7563e8dc26c1de83d1c2cccd61f52b7330fd5cbd62b8256d829047453c05197d555b414f968e6b" },
                { "ko", "b8a5feab8f04a0e5601f966cad3d31398245a71749c7fde23a0c5f1a39f4447600839bfb08fc85d39eb28e7af4670c6272cd2fdb0c3da40f1fbbfb6bd0581fc0" },
                { "lij", "06349731c563b30ebfb9ba21f28d8d4418b25a80cd8f7e350364a7b7de2475c8f317d1564841f135f80deab577b67913722bc845df0192cc1eb6fef3b5fbbb88" },
                { "lt", "a7865c3b507f31fe8a312466baa766e2af9a2aebb4efd50584231a67092aebd15cb36609781507ff96ac682ff496222608b318e582a81f856536c6d6d7753a31" },
                { "lv", "21478167674d82fe784810d78e8efc4942df21c791e8044b9cef5639b842e63b24c99313a32f1e60c0783b4f984f612fbced02f8ec6a95781c1c1b217f2d7a14" },
                { "mk", "92fc2a2a5730d9b532f97992c9a4bfe6c10ae038bbf29ea83f1e3ac2ad9188a804b8826d09a72907142321c5c826ade6cc740ac3316d6a1c6d3083ef59d36fa7" },
                { "mr", "bc4b6c2ea32a24039a36d28e1d2e18cd8d4fea9046a6c76d574c16c36816662fb66b3f129f852d50f9fa313f50735e7241c3831aeb28341834f93029ee7e18f6" },
                { "ms", "ff6744b0da4dd52fd2899f690e50c9633d92e99157597822019570c318cad82977821f1a466898fdb953f704a3b6c07916b82a1e0a544cb3d14258a297afac16" },
                { "my", "bb5c9c126f98fb5b73e9d97f6adcd427948a9e0a87d04f35028eb3cbd30b4323b0b8c6297550f96c2e40d11b1536adf21bc89be304bb66bb40853e06acf8c493" },
                { "nb-NO", "c8dbd05d99a0023d696df58e71c00b0b8e5db0c279235eaa624e40a1f636f3ed9694b6fe58ff0c5823401d0ecbbc4e7dbbc1d1decc8b3229ab7090135e6bfe16" },
                { "ne-NP", "facb72a247f44b45489aef36e12c95d1f6bebd5efc60fcfec217584176a94bbf6069ea3c6cd11ef472affa3d8afe8b987e3f147af56f2f9fb3f053f29e4004b2" },
                { "nl", "619b7f685196d3ebe179098f95a43c041293c41bfbacc85674c49cc486a56adb7c8b39f8d113f6cd59ea0bea4a23b505adb57ea2599fb60b9793d5d0e1452513" },
                { "nn-NO", "2ba519d4ad4b2109c9a0345b18de1d53e0cb1af7f2648a3d75063796ae981ec907bbc508e1dff0bb4a012562f7cdcd1d40b63525ecc9586084f73113c837d041" },
                { "oc", "272c8c6abbdbd09599211273fe4e6a66afa104b244440e4e99c68ee5e6db897fbf860570124cf68f6e2c9d630a5c7c2880819ada83458e65aa88b94e55ed47fb" },
                { "pa-IN", "f8ac294fd5147dff623fc0f4d0602c5763ea78d7e96010c76542ea729679f8c36aecd17f6f4de2039e95e757dc10e5eed4801b46ce075e451e923abd57186cc5" },
                { "pl", "af2a23428cd2ef8a76f4b4100e5be16b29de8f2a80791a5714394504cb750ddc5038a87ade47bb386db9d182978d4b8cf26b14e39193bb336257fb238c4cef6d" },
                { "pt-BR", "ba996fe0caf6929676de369ea88387c24fc7d3354e870e465bd211570609a978c7c824c26991f77ee05849b618560c1cf05e40a4e9bf39b99550132d02c804b0" },
                { "pt-PT", "880c219c903d32f4641d9f23c8f0c377b0d141eb7a7bc2952801a856f5dcbd51a695c0c6c8c2dcd28d03195220300d09063242abae6515306434d1d2f01af2d2" },
                { "rm", "8a967e66dc188ab12686702ce3501e50b72cfc23a27733f96483f89c7b397da4256cdb1c958afd0a02e104984c7d13cdc162e9a6a19f8733badb677b301911a5" },
                { "ro", "b85fb5196c0e8ff17a688005a6ed168758c57675083949dd9c64bc96a1f9d5910e8761de5e64125ef7db79b58a7878f83a7a81e02e5d975503eabcb7dd44ef1b" },
                { "ru", "dde147933958d45e4f95ae9604c60927565463cd1eb796a771af98be4fecc0365debcd171dc94eab16bf0b631e19ee3f79d2d40860b5e2d0c8ff66fb9f13de0e" },
                { "sat", "cbf736ffae2da831c2fe6b024c574e84193f72872a10a40b462cf5d96bc765adafde4d1ffb18dede2e644b5267fdceabad582d33a4e600b8f386a9ca0f22fa66" },
                { "sc", "1f5ed18045e8924391e8d5aaf53857f6ad1c40328f9daf6cccf68c365658fb7173bb6cdd6d1d64e9dce68e778f2f64937f1e50257417d56842de87f3d5f271de" },
                { "sco", "be787c9661e970d8bcf4fe6b3d36a9231f5880ef7c75391334ce1ae42e1a3774f6ca9edeed78abcee1112a6b46132fa08d8d31c49f46bc501648f1253f168280" },
                { "si", "824b53dddc5bee2e82a1509b1116109eb19704e20d7f8cce6befb16532ae3b199253bb85b646242f27cb0973c35fa0f8c4443adc66f5883bcbc7b0a72765cbb8" },
                { "sk", "ad212b2d5aaa298055ad59de28a45c4a71522af7e92183ebfd272d7dbb4a5a7291fca7a339bb375ae0fa06ab1a7a8edeaeab467f58a8c6f25d9464e2532e8375" },
                { "skr", "976f786067f6e50c555501480599fc7569912ebeda061827df9d50a235b4c248dd62128c6065c62aee3f84b519d5ffa686700dc0225120eee2f0c41faf2953ad" },
                { "sl", "20b398a624670e58c83c90a83ec29d659e2b280330fd0ec6eb534e719d526d556b493a4c526eda14db5cf909f99905ba1daaf86dd533d42a3989152f844e6d2d" },
                { "son", "92bbbbf1aa92091231ffbee3c6dc60573445ee92ac5737437a31513ca3089657791af183e48d6d84ad1296c8f11e1ec600895c736d6b98b08b5a013c867fb890" },
                { "sq", "6cdd3ca2407db3444e4adffdef790290705023f8010f2732c0f903ca3d5d2c1087e2aade0d33bded23f8a04755d1d0dfe5956203838067480ebd9dbf7241ff68" },
                { "sr", "3beaf198cf60c32b320c3dba19920e0547e41d423487b2f17ff1742085ec3a8c31e3381c892b8fa8bef3b9f15dca0bab80a3cab4573c84ff3727a5b1b806a73c" },
                { "sv-SE", "19f01d50d49dfc075159d45ad7752ca5a4a763979490a3ca39217bdb0b49aefddce46eac505dde6ec9196a791edef4bda4b0939f11896e7e4ffd474a699b7a07" },
                { "szl", "5be006da6eef4373068bba0848892427d6990191c83d270cb22b987625e1f0966ee67a27bc4ae11644fb8f7e65d04a459e7a8bb6a5c3f5137e0a62214022e3d5" },
                { "ta", "a029016b097af04dbdc3ce67fb0dcec4db8bbf639a255e3036dd9155c044f54cff41b461ed576e541dc9392fa3560806061d976419e2f85247338b4c04983a06" },
                { "te", "56943bda9ad7e406b49112958d9875ada14b41c79e55e8c4cbda0b3e0a6c7302d8d50e1c73ce5e64b4b952c621c570766d9e16645e083ad99a88943e0fb7c0b2" },
                { "tg", "07d2aabb0a38a52f7b4bcb84b3c1186b0d1b7ba928c0f12692ccd6aa707df68d9d6bc6991453c02386f4ddad7c2b2be0f5ffcf43865a25dd62c065b748c356ae" },
                { "th", "7219c11e8bfd6417c98c486335e10275c2babf1fa7cf091c714b038ad1ee5dee2225f08f312921d260932722542afc092b2662e678454fd6d96435f17f32199b" },
                { "tl", "2aa3446cdd8fc737f7f9ad3e7524abecd89feeeab7f95f745399eae6e523ebfb864ab626453f53c9d18a89f640e609beb5490b82f280020e560c1417385122aa" },
                { "tr", "83271f9340aeafc0d86a7e082930a5cd8d7af6378e942c555e3d9ec5aeecd0c003c6800ddcbca446b64715b2e7a98360aec488a7097327335f19afe3257681a5" },
                { "trs", "2d09e04024f0b5efabf48c60b370eb92c6a0f62434d8e20f4c2c27503b664cf893e79431b393dd8c7410ad0a568e4f888a37604173535d084ea4bde0f5656c0e" },
                { "uk", "08e73d9b0e4ffe332c4621ad1be9c3511479bbcad92c54873a5d258423fc66a5e82b8a4a19b8894e029f86c257bc3ff074c0b2a2ca67950a0e6fb8652a7265bd" },
                { "ur", "04526c25a924851b9d1431f590fcab4fe33f8f24628fe8ee087d73d8bc69d83171e73139672a0764a53205517a524c2da28d15348a21698977a6fbb115b74690" },
                { "uz", "4bd2cadb7a9597d1c6083213ef06d159a331ccad5f6bc40650282ccf64f3ad179b5233eddf339dda90c6a33807b50dcd64daa53deaad73abbf6430f120a0b702" },
                { "vi", "be844099bc57eed6743f2be0479a65d0980030c2e23e030c8228907f73ff240bde3e9f12eb7524f2075e789b6f77580fcdd83b5f9d2da2ea74317e5dcb390f92" },
                { "xh", "829cbb5b37b3cce3dbb2ba737c46639bd8c6904c4be87c88d481fd68bc2ba537d6c4b217ec389a5c2faab8d501f487d731c22e59da2197a9c2b8eae2db4bd2d0" },
                { "zh-CN", "e439b30155e5fd08f0e09f279b3231e91e077a3ff0d7bbd125fa16534cb7755590f7c3fe18aa627d75afbdc3e8889f19b06c56b96980b2af3c4af53c538e31ee" },
                { "zh-TW", "b4c498992fbb3c3576c9f613034afd61debb1792fb3eaa94fad99b3a3d15999eba991d45ffd0502176e46b2d5ac59dcf371100759900d6a11eaa9c39633c1fde" }
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
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return ["firefox-esr", "firefox-esr-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
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
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                Triple current = new(matchVersion.Value);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return [];
        }


        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
        /// language code for the Firefox ESR version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
