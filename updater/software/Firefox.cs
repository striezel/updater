/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020 - 2026  Dirk Stolle

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
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
            // https://ftp.mozilla.org/pub/firefox/releases/154.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "191cbe2aa56eb3d3ea5628deaa3f7aa9e3379c6841a5087b71723ce07c08f1c2ca0ad2494702c9f75c25d2ef4a7853d72c8fdcc24c1e607e61087fb73e228868" },
                { "af", "7acc6f53f3ab5b590d7dddd79ba80801cf212285f0f9a527429cb38c778e3136547fe4bf6abbec1a3ac507bd49ac2be97020cc4ecaabf8be5069e23a082ee299" },
                { "an", "475ffa1789eb7dc09418d2c459effedf39a021ecaa9c5b55ded22e902f98ac04a9bee466760b629e89dd4acd0eb2955916bb710d452937c1c26d68f144537253" },
                { "ar", "cf8a2800c6808ce41ff1821feb22f6461f876a363b4b8f20cc0ce2c69a12fec7338f908ca92d9619995f6f4708dc2cf2dea42e5568e62e36c051ef06ed07c3ad" },
                { "ast", "896abc2f2e1d13b2cb598a43208bd3daf54b4f36e813375015676df70fff86249c7238ef6fc69314fd089bf11f988c4a826f2bc238e068669c6b95a3cd2eac98" },
                { "az", "73b906c2c7d0682360ca61f5a0a676cbdc0d465c884d09ba28407fe6a861424dfb583119dd66702fa042c95d0c07c33eae4216aea0c2e5ebee7119436d7faa4f" },
                { "be", "c278ed09cb34ea2e6a98e6a1a4da9fe6689fac7eba9c67282e07587d0247a9f24397c5757a25aee727f13bc8a0236310cb59c4deb320010212527c4f176790a4" },
                { "bg", "60deeaa23f72d71be1a5d4eb1dd0e4ac62949e89884dd63850f3bd0599346a55845e6ff6761fe6f676c9a743f10f26ef3bed4629be9748739034beedd50141c3" },
                { "bn", "0cc674b311d95ca9f425a08540a1311afee11b53686cdcab325593cc6d2f47eaf2279a2b79a79a311a453d2011003652ba301cc42ee36b3a49995b09a5c1ea72" },
                { "br", "f0acb6a524a0b6a2b6a26473ebccf93fa90d263afd4b596245feaf6daf2b5eaa64c92a647d380f653367ec75a2745ee9b432463b7ffa2f261d0e3432b50f4c95" },
                { "bs", "84c5850037ab26a1f341a5a555ded7d88fed8170bd51c78ef77a7e3d106295fcc95c0e7c045ecedd17df88a1b266e357bdc57b93207b3351d98fcfca39bf37d0" },
                { "ca", "9749bc6c557094f570b40bcbbf123bd088cb4c8edfc48799bea40246f2306efc249a6511ae5a37dc89f1f0c262a9b587646fd53866557321ef7c9232069da90f" },
                { "cak", "7dc852aec78bd1e45f2d7b922adbb6dd636e5b3df5bd30452eccd965ed8936e845079b8bfc7bd0ba6adf2392038ef5375eb929cbb2f110fdf9b26bec03983642" },
                { "cs", "ef0a3dd814c2682554c4664efafa54b0d1be6aed36457d2d7d6cfcb177ecb98650ccb7ae675f22584f4efd1d483d4311f69d5c28e8ee082c71bbf8b0ef6c06d3" },
                { "cy", "13cc9094e25fbe3cf53bdebf7bc456a67c7bde524c0e3e4d09bbcd8d379abdb70eebbf89de3eecf58e9e00badb89a206cc00d3572a8d14ad217561e88ad4d703" },
                { "da", "ebdf890a05057e65c47ad6f423acce550f2fcd962e2b6291cba3e4a18f09e7f717206a33c99a3a368a9be52f8022e2ce7db1dba7878f9a0b76fe79c99f32d223" },
                { "de", "632d0784f466a41fe0057eb3cd327bc74e966d06b5990754583c3e499d92762a10625c2a0b95ad90407ba8725c40508dfbc6784aab322e53d96392167e22e77f" },
                { "dsb", "bdddd7a04ab7c8f7cb43f619068038610dc8c1e61a23cc90c0e051745b10c883511bea12fdeaa3ecbabd6227e7f1ab966897aeccf5122508e4ef7ab6cc3988c9" },
                { "el", "05c1e061ef2b2f73c4d9eb85f2febbce8dec87a5efc3141c34f3089912e7d15f60f32fb61969a3f9acb93db2be8e186a80f1dd9db4cd59cd6be2b691c70c4e8c" },
                { "en-CA", "c9a81e10400afda8597c3cadbcfcf35a86a34696425656f8a563e16e86dfe4d7b4d42d01f89acb174679949cf2880d21d6e4ccdb91c49d065ff3a14a9f1cd52d" },
                { "en-GB", "53a25cdc5f8943a62a555ce7525cc2c4676aca334a889916b0f6959541b1890dc531624f4cd0c856b7d4d5255791f262035d999a0af836d6343929ba7282bd17" },
                { "en-US", "6f1f90c63e42f567a0d80d005fe1a68909ae9c2499a0c1fae6dcf829ebaef073e97a09b4cfc6b8eef3958c8e6794256ce8b0423752ce7aeab9a4808f30d6cd03" },
                { "eo", "a309a42f59e47c6579de2a7f47973553f3bb5565de9c058e6c6ae1f5a671c7aa52bc31292381c64708af9778dedfec52846f9e3cc292dfde86ab4502e4bd0f8c" },
                { "es-AR", "0360487096ad5f2e5943f7d2b81691f5800d8bc247642bb34805cef99b67c5f96d097b4c991ff37e7736ff8503f025519af24526b60d2ec2261586847e8399e5" },
                { "es-CL", "d5b84bd329c01c633dc0ea1e9bc1bf793799d0d5cb0e9f0bf991a83102663eb41335182cf6a882f4a1093b51d4be63e200d8476e9ee26f7fe7dd6c7d3483e613" },
                { "es-ES", "9e9b3a16de4a211287b91785355a20192b29c89bb5709f3202e24bfc931a8d17043d5f757280083e71cb231756a376d8acde420360748e48d97d0c6ff4021ed0" },
                { "es-MX", "bdef18cc5b5a7f2a5a4b3b1843107d96971db3f6d4ea5116fdf88c3a64f71180461b4bab4185695a8a539d7979c2a344e41b407ab762613e1427764281ff129b" },
                { "et", "cc2076a5687aa170327e6f9cafd23c5083b89c6f13928e5a78457fe35f95b99d5eb31869c15970ba8ae7962ba6d4527805077ac9dbad342bfe9774d9a8230783" },
                { "eu", "c932d6319d1895befc8517af0211153ca0b53c8b35e21b9adbc5ae006421fac3b340adc09fe6090c97063535a31f5c2663425cb04d84c093d035a69a4a40d741" },
                { "fa", "6e23e719b25486abff3458e590351d1f2979b6a9e8d051dab96b4146db9054f6fed3dd01472d0fc49e94d9160693c75c67f5122bc50369bd45975ee60eeed16d" },
                { "ff", "9d11928fcb5f8a6dd7d7af713a479d1941aa617af010d6bf637455de317e9a0b8fbf36f2317fb6a41f29e685c56dc7ccd2d4f8f61e706d3de644a50f0c0174c9" },
                { "fi", "cb78dc5fece808c108a313c3d71758d0877e171bc4050519a15047a3005924bc9d092bf5cd064abe632c29c3a34744b2dc32b2140c77595c5fc56344813c6290" },
                { "fr", "32961575679fa5352b4242c24749b1c9e1b60ed001b2fe5999849fc782d5bb3511ff22543db4510584b19539957bf48f8ee75912b09e17c5825dd1eb5ae6ac75" },
                { "fur", "dca55d97aae987e76d05ed9d9ca64cf62206f054f1a59ee94bbdce5ded1e6cff090c8d189392942c094c67c052898803829acec366921e102d20db694db82878" },
                { "fy-NL", "08662a239cb06a252237b2daffccc474735b9456c9d0aa31ede3e726d811a8f48f693103ef9e8d7a0cb1f24ec090882fab190d13d4eacf7d886de88d458786e6" },
                { "ga-IE", "3d046a0e5b709ab4e2d46de174a59ca5df3ba5c8539de8a3f5529db7e7cb77ef8ab0bb91441106b65f99ac469dc1521af04f4dd8c632ed487d6a84bcaeb62466" },
                { "gd", "0c4a6cb0718972aa61e104bd5c69b8f6270f146cf20c1b600dc4c4b94179bb282406c4d3adecc16afc062a4de5a5eff4e7d51235de98e1139ef5f2435d7fab04" },
                { "gl", "a25930f39f3c3af472e323ae4054054a9b9cc7e1410cb9c63b440ea5eb563b94f6efb8f5f8981c70d7b9bfbde4bb3829498e656469c5020586f204fad896b40a" },
                { "gn", "9141c5a59b5f491ad4a26d3b27a8937a1764b4dedc37b449f8ca5d86caad0cf7fcb0237a06587b17e3096184c579909cf4a828e8c8aa5f3d535f54dde1d8d351" },
                { "gu-IN", "a6c00d3d0343d021d0b970cd4099297111099dfc66f2991b377fdf8e2862b99a5a9bb92eb7069b19baa409df1e762949cd40ae7166d1256c70745f9c776c77e9" },
                { "he", "94925da786353852ec119083029dfad099d176a26495e8acb556239fb3390bb4d78ed90fae6c49c393952ae8874951e202c80ddde5f2db4dd0577131cd31e1c3" },
                { "hi-IN", "a1cf1f41cb6bd61678b11ca10a1e5dee567caf2a3b15af6b9b2f45af604339cc0d576af4cea5e16c5174d675a5d4a35eec20a7fddcd21cc7698e8c153e0b1c01" },
                { "hr", "295cd1cb9f40278fd9aa831268fa5037cd4e4f132e423547c51d958a19e324abf8c2e41ccaa5c2693b7b1531aa20025f9fa7faf3fad19fbb930e055014855040" },
                { "hsb", "af5235242fb4ec08c8a4a965316d50e4a64896f6521114f4d372ed86a2f956edbb90047bd7215342b87c5fd8c3150d987b219d4c97d479336196b904c157e007" },
                { "hu", "866386c9181a712bf1c1207c4d7ef645520f7a16e89878d56d5fe6b23f6d849d41b9303a5331bd191aa625a948a5f181ca9c773154e56a1a3720d2be86311ab2" },
                { "hy-AM", "7551378bb27053f23b5c7be64b73ab448c845f3eae06006c23786c25fcbd4b98aa14e0a066dbe090ef66f29bf0a4f7e2c295401556b96000ae42c2bb5da61e4d" },
                { "ia", "1cbf762df2c17f9e32be0e8d97ddb05c2b4c346f4f95462dc64c4435782cd1d33eb3966705e41c21438d12a85bfcd8a10dcd56f6e00456c01f23febbc1b6be8e" },
                { "id", "af3dab7a2a869fd36ddf1c80492bb04776015928bf37b8bb4774c754cce80ec635422ef0a4a0569b3b2055c897d42fb0acf84b8ba42df913cdbae1ae54610556" },
                { "is", "42b2d2fc937ac6908daeddcce1ace44fd442aec72c2adfb51a7298d596c064a9add830e12d3f2e2ec748417daaf64e2d931940365e4c50a1bba23a0d859e6196" },
                { "it", "6b2bc692aee613e89e035151582ec057dd447c788a6e9718ef74a0b18bff550c3d2143d4aae42e0275a975556c1559470b50ea0cdeff7996a3d0ab67c2eb1269" },
                { "ja", "9a542f14ad75f82440e30e0deecb23f6903cb2d94ba4e6fc59f6b2271b4e2013c878b797b18b9ad6cd2eafea91898981e3c2ec495a81d4563ca967e143427081" },
                { "ka", "14de19700343f4f5bd72938960bb4595618809fd7fd7ae3128765dc5328d526c0fb2def8c49706185bdc798d5da5ef9cbb90fe7d5dad6c3bbd02f1b2af759608" },
                { "kab", "da2c5c4dd4bf2421010d385e6c2d4c885c79e176975f374e99e0af94ddbccf475e10cca231653ca9ff41c5b7e452ad4a58565d79cf123d05c6bb69b81877c68f" },
                { "kk", "5a5d62980a0b06ee13f7638813de1cc117eafc73841fd08a9fe635b051fac5f789df9c14bff7d5cdef46c73bcb03601472fa1dc6917a477271c11726473d4fdd" },
                { "km", "a7868c96afa6fbfe3f2a9a159a44235278008b111ee6f87a4e1e113062e757172c85719f682db0cbd2b7d92115e916c7bd71e950b28bbde762903ab2193d9265" },
                { "kn", "120b25f18312c16a887a70dfed6e89d07bec0f557f34d2741c54ac2fc9ee3b5ed83953a058ebbe028d1c510c78f87330f5b18f6ff204ce91030746a42c8d0337" },
                { "ko", "15af80813becadd2856904f2195e8d29c0ee8aba7bac3ec1cc206cce7b93d4a1b669e6f5bbdf7883315adcf5389fb433aec0cdb295e534a72313e282629a294e" },
                { "lij", "d4537772340ff5dda308fdc06df44fb580760377076ebc299023775ac2c7df36a6d43ad71f502f59ece3497f7a4aa491f6d51c779660b89e96a92e106490db34" },
                { "lt", "bf328b47f4673ede1068653ba9c515b240730f75d36bff15446163f300e65d90298cc6dba8e23c78990742577f12e092742e60a6edc07127013ac43f48d2a265" },
                { "lv", "9d42365e361d4be03309b71652b9bdd9c94a38f8156d7727881b019d4d236b06d4a1a0458fd9098ba16b20406cc9bc736c82fd7394b12304e350b7bc2069bbb5" },
                { "mk", "3bf11a272d79855f5b22fd0be848baf323e5c6ed62fafc7690abaa0fd2368e9923ffe5153aa40b05b2c1eae34e6e7b3b13bf2270a530fd5ce08fed93cca21630" },
                { "mr", "461bc16801857acbc1581d8b8f5382757d47fc4e3e8b99e5f1ae2df706eeba57fa60c39f19cf5a06657cf2caf7151f6ced6e326159e039888fbe696372574738" },
                { "ms", "21614047de6740cb143e7a0250dc8905394fbdcfa1da843a58b819a0f70819ea6d054ec9a471f7cb3d9b6b0a68bbb8b9c237ca822dfe8280d04b446c448924f0" },
                { "my", "6a6b9d3638a124aa6116416a6653a12b43245957b5d6d82ddf19ccbaf6ec707bb225645f7d497992c2f7b354716f7ffa264ca963f6da790119695a156487e074" },
                { "nb-NO", "acb0f00d1455367f15c022cb67550c9b2b5bb91bc2d344a8bd4b93d4f793f85a5ba23288fbcc26e98dc295c47409d82bc4f3e1de17b7a21de015f692edcaede2" },
                { "ne-NP", "20c971e29c7d6bcbac5cf86a3ef021931fe16815042b4c6bd2a896724d8be30763bf34d77e7c03321105a705f808376cbe9f16d38c4721955586c757584876c9" },
                { "nl", "91876512a291f2668e2621b6f3fc3e4f20b81bd24cfb6336e537c5567821a93209f0c88f42eea92899080de573b9f65f6e1fa989069d52fa06746ed8dcd42e17" },
                { "nn-NO", "e3bd73dff5633cdeb8111c2df2d9bc20027b2c1429f3307b6d20fdf9e917f31047d8679c3640e4cdab45b4533749656f9dd36f2a8a25199fa7f2b69109cbc24a" },
                { "oc", "efe4d13abbf06a03adf75468c244106d8893d2a4655e1ea31b3bbc99e6219ba90034f7b29b4e372683344ddf90a8b23aa8878d367032a2b070604f66f5f65b3b" },
                { "pa-IN", "9d58f7a765dd87db049be27c8dc29de6b1d34111b2a4dd9c3a8d70afef6d44a33fe8e130519bc0702e2087c8f006bc6485c52f395d2e4a1c37892f2d6a29e847" },
                { "pl", "c40ca843c11cd33585b819146356cb98c2452021f51986e9bc10a6f02c3bb810b4d80d1f5abc673f54ab6aa651d603cfc9c9e3cc374c99c01854f29b2e2e41c9" },
                { "pt-BR", "4e45dc11c2e33d2101cade612d2cd9a9cf82d674e36a8df3ad345de7b0496df5cf3b5c54734e40e7eed09022ab063e88c265dac9d7c9d6359bf26ae43c317647" },
                { "pt-PT", "61c81151630f2b7acd481d13fa0362fc3421ebe39abd96bf7c47e7c892b230a63a6a53a79010288b2764847ff6dd9373326c3f077dc5e6997acd93ce568bab48" },
                { "rm", "71afbd7e694df5bf2236dd15ef9555afcf3101e410f7e20718571a27de4b2c3d48e9d03b8a740d14f2ba176bfcf247c818259f03af0b66c039d6fab482b32849" },
                { "ro", "89f36cef7a26facf1ccc37ae3ecbda855d137fc18d598cd66d05e1c84ebc3345cb164a9d6057271e896c2244057cbc4ab2bee89485432bc9b628bed1ed3ad549" },
                { "ru", "6d4d5a4d85072ab48b435c08e32ea939014e68500d448d9df3ccdea54cc67a6c63a432be1687ca2f4a8061922648cec6e9c3ce14de7c988cdc541f5b62dc7569" },
                { "sat", "0dc20f61d023bc6aa0e01859e06266f6911e03be12cd15a122ffe2bd2568c1d37ee2bfd1fce019c34a5918ae6bd5799de6c66dae442957371d261db45a3425db" },
                { "sc", "f67b84763d459e6b1f738fc2c3cae3f632fc0518882d281a4479df95d5d31587c6fb01864dcc804ce513761bd97832326a00c3192885ecb88d9bc487effe8c5d" },
                { "sco", "23eccf87fd5eaa1b8457e698d2710f0d1152aa861afb5839e6f228e7804e503c0222001703251bc52e49f92291f3f89087d6b3e68ba5470f57b53076e21cddf1" },
                { "si", "73a4c3cc0a08f163dbc2d2c48bfda9f45294511dc64b0501a7c66664b9b1fb83c3e40b54d4330b45a6895af90c706d2d961fa4d4ab9b9acd91887fb18efecef0" },
                { "sk", "643e803c15e6bf12c6d5368c0e0724323b4b3491b73b9853d48ab7d939eb53aa8dad14f5c7284db4ee969c3c880b0b5f3135df12d1cdf9644d35244cf1ead749" },
                { "skr", "bf1572c340fb136844015f20f1d204c02fdd4c356d9cd54276f63f8b39a94b49ae48333a9041724a1e7db72569e75afa3df1e65b5d60a69440fdb1031f63079d" },
                { "sl", "b813ad692bde3d3db9a037d43c8fd37fcf7d07bdabcba56e91f82c1e086ecabd73b2d0f9f80c638469eba29a33eaa330b57d6392bf206d567f71191205fb33c6" },
                { "son", "04d292061dc1866abbf7618eec8ff39f82f7aed47da4f2f304a45cfb8ff1c291be4068d2819cbc9d979513148eb4cbc902351278ca5475ce04eebf6a01a28d31" },
                { "sq", "4bd39d2d76ead811a689d3565aab42755f22bfd4ddd0aebbacbdd7243607bc790dc9becf5e6c6363ab0730ac29f2f01e830986d4bfe0baa785940bc3d551410d" },
                { "sr", "bad248f9404fdeb0ddc4561a514260e7681e8ebfb482de4f4e9e6d189decc99b38f5c78d3aa3485fbade25487ccd2c5f84126b608e99ae4a4e963525591051a9" },
                { "sv-SE", "92915656bdc452393d2f5969ddda927aa91d5642ef11c0a2540b6bb77c989dbd549ce9f1ac2a69d8d4e1b6f5676b8c8ece53da14d457cb528872b7c40897c606" },
                { "szl", "ed8035cbc072f0412120a87c0a06e5a9dd155e5553c8a837890b26f9605d2c69e0fe2060e32a6a631d9e8e250833d4a0c9a4e0e8c646bc3183f7a857a014fd4d" },
                { "ta", "e15b7aafe1313acf143f4e279662f37604115965930303f8e5d34eb09b2ebaba857d424760b33c92407b43451184c9483274cb7b17a3059ef1293983aa2f3995" },
                { "te", "1d9232329bb3be2ca63ee041da1256d0eb2f6d252a3b0418ab1cc2d63d13598ddeca5fb6b65835ac1222d3291b7d663d874f901234df1c60048135f74ca1257b" },
                { "tg", "85e04ee2de8bb15328392409444f5aac24c07a5dee3c66b841d255c133fa699076a5599f0799e91a8ca5b767761657c97e134369e0e2230aa7aec5abdf2a1797" },
                { "th", "77d9dbcad9728fa28316f755ed1458f97c0cf4148c7d0a7eb75227dc6a4ab3dbe9244f1bd6711e0b1f81d32f9f49fb67fdfb6d767b87fb9e147f320a6e05c784" },
                { "tl", "2a0c9d90b61a13a36108bcdc7ae19ee714a025c6db0ea40afe931f8372d3e17a822be0c3cf6ebc9ae8d03101daf8666187502b35329a01c760d40e52f0d9ce3c" },
                { "tr", "852247578a0979798cea2189266571db8ca8288641ebdf7d65bbd3d8172a54bec4469a9a44c25f1547dd9d704a4d8f5533c3c18ca3be1f7ad7e3d0cb3fc9992b" },
                { "trs", "5eb1e0f59d9a46fb454818494ef9b164566a2367820f7575e48d1781597ec8e165d253f74ad4047081aab362de85de4a512b0ce2800456c9885bc255f523c2a0" },
                { "uk", "c3b5a126862fbdb5c7b9e279babb2b015a14bfd2cf72e3144da463290773f9580d7a319b5a3db2b2e9a483eb4547d865c897292f00ba03408133b35eee1e7f97" },
                { "ur", "2b329c347771e784939b2adc9747316bb6c97beb9d92b9cfb7c83e7e64dbb1902b0355541f306b366b038224a5aa5e5b92d76979bf99d025d921f12626cdc152" },
                { "uz", "e2fd393c201a56643affef897c3d2cfa55bfb735518c49a4f6833dd1c75cbf430674e16c845e6efa5ecb8e6a0db27ba82a141cf3c605669d3391f659d8166ed7" },
                { "vi", "856f230a1be766b7d1917bfcba2911d424983ecfff166f9d939591e987a0001d329bc87e168d80659fb61fb0d26a4f84f8e566df10abb3844017f486cdde8f1f" },
                { "xh", "ddb479b385002cc12ed9685100919d31a1ac02a6bcba54f4c5518e6b25f26230e004e4264bf05d0f4df524d79356f1911e55159fe37c17ad797f3cdb8cb1ed88" },
                { "zh-CN", "f603d2eb82bcf539a1d77f70dac83c63bff6f5ee80fc72644d88254b71e67a86d942bef0dd0d080e8c086b6f3faffcf55e73d6e083ba054ad6a7846d45d6d081" },
                { "zh-TW", "7c591bc67502031cc16dc4e883ab0b5a6a3ede9aeb1422e4bff4375e0f2ad06a178fd80e0971d9715c7a033c5658e73042ccdb87c2b3c95f140dec24aab52de1" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/154.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "b08fd128f2818d5cf6ff031ebff725407a4a0ecd389c500cec760977379c6b61ccb870894c4e944b711cb990f3c9f5ccc49c92255105736887a343a8c37cd758" },
                { "af", "893ecf1c63ab70d96273cdb9c7374206189a2a854a7106d84247deba177900a3278c0744149ca472fe5fd4b1778bd5cbd2d083379f24e27f6ba2ae53058095d6" },
                { "an", "e86e362e8e3bfc372a32f06ea3ba100f25c813801ddb846d36442a268a94727d3bfcf51ea20bae3dc62e8b0ac3155409ccdfc9de6b4f41b3d66bb7572dc4c0aa" },
                { "ar", "9566fbff5def24a056cdad84a4d5249f2c8b2820f5001e167c226c0acab8e5956bbf92db8a0613488cfbac43f0a0a38b4436a56e74488bda122f86da874d20a5" },
                { "ast", "5de2ffffe89fde99642ad4f3854838ec6a9f9ba74cca6735160d3f9268c242bc0b7fae8dfe8de8369316750ef3c1c9501ab96cd4b272826087493fd25e56d49c" },
                { "az", "a9a8f0c976d27add8382cdff36a7dea98bd0bab1ff132962e66b47fa798f067c20ec988d890fdb2385ca9c59807abba087f34e375a9ed7f7e01f63d2599e6e71" },
                { "be", "b60bbb458da7bb33bbb63ad30a3b32e0712ed741d9d01c43ff3af5b475d08537ae6ba0206067b3b6179876f7d9938f1896fb044ea42ef44a293cd2fe41970eb2" },
                { "bg", "0a3abad6e3d18ad7460c6b80c312fa70cc1aba9029de117204eb6cff06c3d5c6a2c8ea70d69342a01b663b764e78856f90ccf8c32b35ce71d78f335c5eb4dfb6" },
                { "bn", "ffe9285e87e6694385b8743e9cb3f2a7e67e6da78f62cbb305814509707acadac3e1071d3b89d2be919c245291618ab0a6fd12fc380cef52b44c1e6a771f3dc7" },
                { "br", "bf12ec1876ee3a5c2a7a9c9c60654bfcc81b8cd5ba7c7a848f5d4c2bef0b997335221709d349aa899001773b24f198b61e14b10639f566e89632ad244332920a" },
                { "bs", "e8b4fc3f1b9f42f7120717eb70671212e5916d2daeb79e8a997c2f0af9fdd3a2d4cceb82f52186277163adf04a70a28ddfd1aa1eec875ef897258d77244425dd" },
                { "ca", "39843a50d13840df5cfd85628766ab05e13acd3a578f349f2c9ad4efd7e894cc8142955c2146f6867ec29454ed1b6043b77354662269a97764a78ab586191c37" },
                { "cak", "6267f6b0b59c7481cca3656bc3df15c67368b17c00649f4bcc803f402327d5e4913e4ac239ed3662855eb270cce250fe94f2b9048c0ff0d58de816fbc5dccca9" },
                { "cs", "ec711a757c10c3e8afff82743d8a65ffd5d4ce4b4cd852356c4c4a9e47884a37a60ea9f629d38d6764070746ff9d6935a3b03c016f3c17c633f961ba06a4f173" },
                { "cy", "6602a742f90e99cbda6d4f247a83a5e7ff0efeff54f66d6c74f754ca6f248ba1ab5718de1c833e67f63113028284503da51974a0b040940920cfca0cf30273b7" },
                { "da", "ba0b8a4a8794e56155f481540c75ea854e5b8dcbbb270773a742393180296aa353ce75691a7bb8447c770ab4cefc1e68225fa27b629eb12273c8378aaf6a5598" },
                { "de", "e2b8c136deceae52e6d8e745df2044323ad26be63638d8654e423f41bccaab4778c9c0ccc6ab4f3636b87153ed834ffdf024b2ed1503847da990edaf5e4f0bd9" },
                { "dsb", "48097107a3ccb9c4c278fc307f4d2ce76557aa96f2173b974971cdbf38fe03a575e39d54fcebcb030b9c62af4158f4c0a809dbfde35d340d7d36be86600d331c" },
                { "el", "452e93816ed01b04e3841ef403117f80d80461b17ead719eddfce93760ac9efd013a8c894daf54bb6a5f841122d4899803b6c6eb2a63dc80490298d3aa223b91" },
                { "en-CA", "5f8a1788f382eafb111db9d2eee2e69eece60e0394b81554a5d35923a8ebfaf4248bea288d1f1f2ea83f9aa334ac16ef1f3a1b1489c607734a3694d604cdf4dc" },
                { "en-GB", "a02e861672c1fa7c1d1bc37e57a552256fe0b8a04d37e4ade19a3a245ff1c40837257e2676cbf2296e3cc56d2bdebb2a52caaf1cfebf10682ee8c08fb6828a79" },
                { "en-US", "514dfa9f8582dc1b693f22c36a922a4fbcb22f3419c8398269253bda655a2f8451e18f156a8ce75c64bea76cae582805b2c3266adc4febf47e15722d1bc35398" },
                { "eo", "38befbf9ecc5af04924afec723af51d5fe917486f651a8d8b93db2c88e20a72d216925e87bb1b96ffde428d7a93e934022c269c5ffc2cbe83174d7af13dea140" },
                { "es-AR", "8cfd5496214e81eb43c665a3d530e240243da6c9857f9474c24c56709ad541fb8914a9d04b7e518e2d88815d6dde70734755236d1d60c5df84da6b589b56d388" },
                { "es-CL", "3b3b2f7ef490858f4b5f98ee7c39039c90a145e5b15854725119799bbc0da5808717d536abb743af23819eb524d57587bd6acd7d680c732510723da73edd1af4" },
                { "es-ES", "b71dc283660d19aec7fe2001eecda10a9e8800543b2874b28b4dc49e01ca42e8062b44fed3b8b3e4f3c985da58601f6bc6aafefc66581abdddaf075aae7c8bf4" },
                { "es-MX", "0dd0c87e12f307e7ec6082214f8385d14b0f57f6e44bad5264ea7a5ece514007e4cb6048cb1c4274f93cd3070c8b3d7e769395339eae4ccaa68a79628dfa3f57" },
                { "et", "1b81e148b6d75a506ad9df657753598ae3ab2d078aaae5262d54ca2bc29897c750d8be1655e044f24b9f41119377ed4761a47fe8d6f51793e61d196ef74bfce7" },
                { "eu", "0d2f21b342990bd27655e895d30d3ba572ae2695c7f74af23cdbfe461d01d565c23f9f697ad2d93dd79fd38999c521165e7bce42eb9d7cea55cc0776a4a8a67d" },
                { "fa", "b7db24a03a7d806c1a78463e905155a251bc36193f7271bd0ef0be8b7fd0fdb946d81eeae622842ba443b7e62b4977b8a9d93e6679b73b2575ca1c7afd646291" },
                { "ff", "992119cc49dff568cae9bf742ddaff5621cd632d534ea4f7b95490bbabb0c46435bb1c0e14c414a8638b3f354ae76204681b565b3591ef40edb22e33e5d03ff4" },
                { "fi", "8d13fac069f022898f408ed8a91b061576b6a38c1b45ab5b9b54d32a57ede805f64ffdcd9cda154d0e8c55d186e8ecd8f2deddfec87a9da69b62bd3638abadaa" },
                { "fr", "248e1708474bda92260b96659e59f8ad023147ad495888ae644681104b138a4dd5bbf8633465893e9916d336a735491f6cd9da5742c5a4065d84cf191dcddb3c" },
                { "fur", "a80e0fd3730b443af74aba861fc27417de61dd71806e65264ca23bd8d1ef20833ac9c285f4447a191b70ce0cf63031c1564ee86d847119ff8464e4b9bed7f12d" },
                { "fy-NL", "11658b845da2577001b22f190c7b6a769c48976027e94f8a8d468783dbea418498bca53b61895c5ebcee053e3e1e49d94c6511e63e63bdc6ca18059258972698" },
                { "ga-IE", "c4434d1907ee5eeb1257be296e2f5ea375f4485ee4dda200d6433ebf2477dea7ccfbac430f69a023299513ed68ac311d90285de9ea43fa1a071778e11c6a87c6" },
                { "gd", "68ed1d6ed7f0120c32f9fb997684ed636e609ef8916e07fcff7dcfeb3b42801224fdcc312614b74300c2b26fe78a0ef8d89579b529fc7e66eade93f279ef24f0" },
                { "gl", "ca223b650bc462ff534367f62b6c91b989358bdbf96857a856665c430ee15e923ce33099d471550e1a92d2422d84d139f95e043cab25e4afa42986c0aabc9cb9" },
                { "gn", "fbae8c06ed725a0bdfe3de5f63dde75fffd162b4a0d230b4559083ac4ba01f2ba17c9c780534ebea133c307fc6d23a154372ba9e723f49a2999f1e4caf4e0aca" },
                { "gu-IN", "ca42bac6e02cf44dc61191a5e0fdca6f988f860fe4d9f692b61b5dcff2bc818a5423f33e8c1667fe908c36ee5175a9c054b0f56c45fea3be9a5d0a9205c80408" },
                { "he", "6d41f71c82a6bca447b0e325d08dc95538e06c488995f5de08ee37aa0abd5ed73c5257e11639b6bb17827bbd69ceee6648fc820afbf4c079a912294d266f58c5" },
                { "hi-IN", "82fc92919a9c6bfbf7bc98a5cacab14235268940da53bce783eab5e99006303b8c1401b19bff1f49075d3637e954a772e801216264d88247563c3fb695b3e1cb" },
                { "hr", "6a30863d365380bd32c8814d7252cb315b43bf2de885e5c42c1faa458dcbbf605aaef7b03c312d7be1c9096575ce6356db3cd6e9b8224887e96b9b241879781b" },
                { "hsb", "298f35cc6b649888607a28638c957d9e4e21895b7ea69ee6e4bc7dbb940a15b2f6335db1c5bfff9d734e7ccfa216f82bad4339169cd9055a3b4495a6bdb54191" },
                { "hu", "aa3d0b58c6afa95305834774cafd1721703b20e71103a0e372ebe5a4f5fd4ffbb85d9998318c8b3bc1f9efcd33693374fe3d5ec3a56deade84c6232c520c4dc5" },
                { "hy-AM", "1ca0c7acf862ec4bf11e6641c97f463b7d7acf1d38b4fd5f94e3b319d778b87b0598c0a21bf61d2336308944d060b9011ed18295300f6ee4cfd9158dd186952b" },
                { "ia", "eb22aa87aa5ee124a8d4f6310914845c1ccf15775f9e05203dc56ddaa448df4b63acf21e1bf201373113bf49e03294a3a924af0c498d02237d4d563742200e15" },
                { "id", "53ff2ec01159be1fd25e90a151d95c7e1d8cf60548f6fc6579c0e8d0788dc44d849dc98f7a509cad090e1473f499c8012f6708c9fa58b37e753326bc482f9fa2" },
                { "is", "a9aa98ecf0b8a178cb824071481fe4698bd3dc941e26de270fe2a087594d87d65a29e75b340214282f6a2f9e25894a8661de676ceb88c29e72c8587d5428c5aa" },
                { "it", "18f98e8f66d0dda486d945279ea48a0a4956771df4e7a237497581e68f55c04883a5dff47e1f9d8f4ddd2788e5aca712a86cd40026f5280654636fb506ca02a1" },
                { "ja", "2789cb7daa1375569f6f150f35b234ecee47c22ef862b5021b6afd7a10f5ee5958d5020cc06f036fd8b7cdf132d4f0ae90c07518e134da9530970e4fe31145a8" },
                { "ka", "fa904c3e9b7eaaaa6bcd41fcd06e8bb71d2857891993e67139ccded63252e52c9833e4e38aa193c70c735f5fea9de2105862cd31504f08d98eaa7a5def679eb8" },
                { "kab", "875116bd7156e815e275be93860a8623ca1d5af83da3f8e3c5eaa63666b5f387280fd7c7ebbf782c4e1b7e6d8d60c0c85bc2233c30d3d447cbed9b6a2123d766" },
                { "kk", "71dab0a8120d6fb04f6570c8eebe53c49b649ae47a85cbc720a131dca7b044152ba19a982114a90df776cc338c289b93e7754348a72de318ea21608a0a9c5a2d" },
                { "km", "13a1d554efc558801bb6f16dea677a1c04456e767a270ecd8863800ad85b17f710da0c6a7793403874ca6758aa62ce430bbe09bfdd48e565a9b624c4caabda80" },
                { "kn", "0442de8c47d817897a2fcbcd637d7b45316b49ed16da10cec7d9c16bf44ae487d4f15fb18b0bf6992c98fe9a3a5cef2d4f2295de5d3e27a458535a42de8f222c" },
                { "ko", "9a852b5bfbdf99b9510127c23ca42fd057277ff32dae4f3353a4aae6ef2b3aa0839400ba22b5caf400569e35935ab03bcef891f95833438137e1d9d4fc00535b" },
                { "lij", "a17262f8441aae7efefdfccef78c1f49e03fef19f869e702a2f969c88d582661070acf40c1b6fe8bc269c790e5899b1386c85ed3f7dc2665bd6fd69b63a270b6" },
                { "lt", "964ce32136e0447cc4ee97e23c307d46d5a8344a3e798506e13044262558f2c59ca89da6942e2f1296c49e2094cf7511c04b251feae2555f1d9c5a2d2a1e77f4" },
                { "lv", "7de3a1b0f8c95b160d3759fc758336de6df6ada6275e05f58cc9bee58a6600d5813ab985fcfb59ad28f562273473f6c2a6a19fd956c8ae6a291aef7a88f5a0dd" },
                { "mk", "a4e35cc045c2b8ec973be9a258aa47ebdfdc1702b4585a023b6bf64083874e1d60c6d6521af8fed07934316d805981447b1549e2ff73184670a15eecd2bd4faa" },
                { "mr", "97695800a7d3a9746526319a57d4d599df8f383628dcd904864f6d7f631026d62ce3466b6d203f35b24947229be8343111aefea2aa025043360f7f76ad2702dc" },
                { "ms", "74974a832e9a3c9a63e5eedfbcb30aa3a33048bb4aab3360f0ab2dea421ac47301bcc0f16778c024dd9f9fd772ea2ebbfd9dc0b7a0484261a7feb5932670f211" },
                { "my", "b7944b301b3e326012bcf35239970aafbfdcbdb057c8d25c1993f6bd3866bc065a901a0b865f9a2d5d5f19c911ed83785b8cbb88e6705052807df6502f707f81" },
                { "nb-NO", "1b38811654274134f25f67d4ac9476fc68a9ce4231921d94815af3e0fd859bb60f0668b0c54c18d1f81117be3e7b98b50e9e0303ace5625c39530a24cbeb685b" },
                { "ne-NP", "e7864421ddbe6a5e37c7d887eb5abf10e496c895f28e48995e87ae9cf36edcb5d5ff89710de6173e312ceb3f67bb59e0647c0a4eb16edb0fff7840e3a4819273" },
                { "nl", "fa9fa473e2727086a8700e39ab7e1c40cdeff278bbaede95720488ab41dd3fb216bcdc8c43133f57a168bb58cf1d104baf6f1a6fa4e5620ad9a7e06945fb7e58" },
                { "nn-NO", "022f755c91ebd02d9b937a28d6cdb08c1bdc9c1e61e6cf9bfcde7a6f8819b478220b2446b1a7e1763d117bb05c052106f4a69463456419a3e525101db1a27ba4" },
                { "oc", "2d88236c3c67d6357593791938d0a913f5f56102e76e2365d248ee75fbd67b118f6b3d9b14d5fd5cab1289517e306926a6a41e3e036d97d6123f335ca9d2a568" },
                { "pa-IN", "7454a97d5c5547a5a4a3a4a1583d958350f2a09c3346e291fafb8dc3aa5235c74b465db444fb5cd46073d0b6996fc87e69fd8322f8834169e601e4041c28339c" },
                { "pl", "74693b5cc4503557f40f0d6a012d0cb8e493f31c3ffce082558c1767dbb3e6cb482e1b69399fcd591f6f9a1116169e48354a8d5f000779510cbaa1359cae858d" },
                { "pt-BR", "30dab4bf0c1c4d12392ebedb129a6a42d8f955b709b88ee4f0b59d3f27c05c6fb4d52b54b800a36d31c51ea16aae638e3723bff653fde9691e9e359c9600fec8" },
                { "pt-PT", "1c5c7f6c058e2488a1606486ec216041a8d7a725c36fdca34a5ab28c5588319af4b2b7e4156e7b6fb0462f866df9200b174e0739ea32e571541a9d5b82e32cb9" },
                { "rm", "4db7d4479a4f9d63ef3bb6c84e518c0363fe75c67d7354f724c1919a65744687a39e1164b0da4014cc67745682327d2f6021aa5a34d40615e37fd1189e0379c5" },
                { "ro", "1d96de78033127bf9f8c69c3a13362bd732e12342174af011a4b292e1b6a7a0628100259868f8e6931aeee07a6a4a7517b0b9647f853b10cd01f8aa5ab44e1f3" },
                { "ru", "33ec0cd1d25f4fbc1f6accb2dde7953756934604e8ec732b7109de3ce73d2b69809abf8ca8c81f6820504508a2d05c4050fcc66ba2183c94fd72671c2f37a08d" },
                { "sat", "c7207583aff96050ff9b531932237a4c13ce88df0d47ca0b189ce8d0455441665f21a4c03229581baa7562f0e6442ec7cde6dc7124d049b38678c10ec767a5fb" },
                { "sc", "b85adce6269751896d0d9cf42f1487627745bd35e6b353ea6fb0f910f1244202ef5fdaa7d395b93825d8a8f5641166a0d6ffabccace8f1ad1ae0d5c0b834b630" },
                { "sco", "93125247e41cf4ab1e540cdf1d93a01adf0c7014ef0879b8164a33932bf3521f694eb3d26e8412bb9bef36e1455d1fd829da0c34e6697cc1b2b5bc4c9d56407f" },
                { "si", "716494268e7c853e5e6ac565bbd387a35fdd49389ea3875c57a61ab3da2d34ca83a41b8811a52f85120d1fb290299e28533a40fa26926646d1d887dfc8615667" },
                { "sk", "74f8891c9a76bed6f737df2a56efdfea76bf8437f5b95bc767129dc925cc4c7f4e501b0a2f5d7da72d91a0d607f0308369886fa193647d8e879cff44b3376b74" },
                { "skr", "5cc9ff86aaab281517a3dcefb729a0f735b1c248224fa3c78cca90d99aa03b381478778f5c03308ccace679532a937c81ca774fad6e7d35f457d11f0fac0800d" },
                { "sl", "af0cb4f7a9e0ad1dff3361ada7f6818e25aa6f0180e4ff2660ad876625195d66a79a6f301a867f270b81e1911f2b4634f38ef0c0685ed133b81df6218a6dac5b" },
                { "son", "19e60f06c34f229f5aec301c94224f6a9effb4f721077f6a678e4bc280c01e24dd588d4f70d9a22b8af21a8d88526121db67429b7f5d1f90816536d09886ffff" },
                { "sq", "a9e6b5ea75cc444e3b9cad7bce318a0432308c2122577a4b710fce7646cb01df97dd793ca01fdffd3f8cbe9a0d5196e3c864e13bd0584cc0f3d760d57dddbb52" },
                { "sr", "68962ef8fbc40666bb5ee7ad69a0eba7c4bdf1f877956198c4a0913b82538921c57637bc72da48fbcb5af516645edca7f110142e03061f9aa82e832275ef7a61" },
                { "sv-SE", "9f2c9f0c8f47382005d858fb05ca7ec0022c4de234c4fdaa1f831dfdb52f2f527f0f03997a0a2125f70a2ee67775f9085ab8315470462567d1b51043b5fdd08a" },
                { "szl", "866dcd28069fcf34fb925fe5767c1a8ab58346bb7ec06d180cc6cac689d6ac5ebe008b706856b7dcde9ea3a93460e53a8672ddcd3c118df4bf6587b1718bd9f4" },
                { "ta", "74122f649c08a86cc8c96ba55818d8e61db470a64895d73854e149a693b1fc01d5e499b5441dc9e73defc3118e3d6b015940f0be9bb6516f55cb2ec9b13b4aee" },
                { "te", "f32508b2cfa83c31547f08ceb5d75738b57976f6cfc25bf67bc4c6665adca41acd5969f73678ec6905c1b6f8ea4b3497a61d12529d70d8edeae4e225dd4b848e" },
                { "tg", "31152ef43bddb4c2e98d2f5a06b8f82d49bd915dd9e46742d7fa271aa709458df1d9043d1d235d71ee19544e90aeb26e608fa00298c28c1eeed5320b6ca0d4f8" },
                { "th", "d0c78a8cad2d565a941b2b16dbc8e4c563a7770ca5c58929f45fa012e9ad57230e34c174c9622e6e1826344ae5131bc9b4aa4254263d02aede9a1f935a292123" },
                { "tl", "05f7c9db29c615a286320541592e5a616984d09e7cda1456b7c39878e89f1ca515c713bebcdd2b62cc843b677deee3bf7466cffc6db4961bb88b8e97c6679001" },
                { "tr", "38d88c6980b673bd00a363f50a15a7a0cc810dc72f9dafba0c788a27f9a1eab5ebdd3e96d41107808a9c685020c1019c4ff720a17090656b0a3708f3fdc6199d" },
                { "trs", "7991fb8d9fc5845cba6701cd082ff7d2d67368bd7f17dd4ddc442c3d032296f697e069cffe35f8c85791d6a47edaac0b7dbbef8603e23dddf31b0da223b8f297" },
                { "uk", "e035659875749d8c8077790ca79fd87b005eba4f83f4782333c11e722ef67d8e3dc77bae4f2c6ae77650bca0130d265e7059f4fd0835cbe397c9f8b5662facc2" },
                { "ur", "c509179f583d61c5170d3f69161ea9d63568c7144ce7b121417368646d65326c8f826d717594766c353b05d1e3bb636d9a9a36f8f1f24cf5bb6b32882b2e9829" },
                { "uz", "51861e82d777ec5b4270f9c7e5c3d6ecd3cce48f619d143991a89bc761a6540255b314c4f3e13b2126615f167a3760d1005d8ea2554e99aefa49e17d1b85850f" },
                { "vi", "a7b69d1ee9f0390a52c12a87b15f0c51d9535ef2a89164db0532f35752c430826a8120ae2316dd1a43ae364fe0584d87a061fe8f35ad56f1d5fae20275d39ff2" },
                { "xh", "570d0dd92540fda5401230fb560193839c5a815c74d82b1523d6afc8eed8f17699e805c7048ce2d02e270fc420972809b626e9f37ddccbf97808973fdd4d9829" },
                { "zh-CN", "8b70963fb5db8f67ffc2583d92c990ab9800b7d7f9b42ecde4558243e9e600abdc22714759194aecc43ede3d1fec9d2a57dc478ff8093a254db87c03416fc355" },
                { "zh-TW", "af3778dc8cabec161b2fead13c600ab33a697925e1a73211313acf43fd9ec283405f5186760421e95857d7aa3b02748dc62eecf858651e248f11f0f7bf9b237f" }
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
            const string knownVersion = "154.0";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
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
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
            return [];
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
