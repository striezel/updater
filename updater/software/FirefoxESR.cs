/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2026  Dirk Stolle

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
        private const string knownVersion = "140.16.0";


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
            // https://ftp.mozilla.org/pub/firefox/releases/140.16.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "c545559b3e54ab4540af4d4521709ea17d41c156d63d6f3ead6b8d04f84e03dd3e2e58e8b38d940c469f2ad625a35787af0c580215d5eed225df7e71edb3e6a7" },
                { "af", "47ae9102a63639562d9ff33930529eb2d1dad799998f1532ef5013adb886c775a34403bb09be6ff3fe38412fdb1fd7bb065a4968ab76ad0d12b7643aaa501432" },
                { "an", "b116ad31789c3489d2f05fbb161c5242183b9360892a211c0ef10de5bc38b3fa6da6c537b19f8938c5fe328641391595b613e5c396900fa4e57a13c61e36aee0" },
                { "ar", "67a12e68d0148614b8b599c12f1ae71e265a21787e6e9724e4166121e0ffbc975e3be46379de5bbabfbc177b7f0a2228edf98a08b76842d62bc8f449ef641d55" },
                { "ast", "6c56f0ce6f3dfcc40ed062ec61c744bcf84018c32fa39f5fdeec6f0a9cd6bc623969a0b20bf8f6c2142ab183f96585f6fade21bc38af4b006c2c58b3128e2223" },
                { "az", "8235d6dec879424cea49f790252b0661ae2395acb6a0968fceff02712a5a473bfccebc8d96cf9a2c13f5f506ddf30ec090a1d301c510bd396ce407b9b2f6b76b" },
                { "be", "fbac1d5f25dd3bdad0ceea5d4ecaa0713e95cb17bb8c98e57eb235f5520f03ea0c7f6c75b134bfdec4ca68ec2fa1395028ed02d09fe0777885b667b668b68f45" },
                { "bg", "48ba1775474c5975c9911f5812a9e39920486e4afb27f4786b32665fef8105f93a36171800a07a43ccf998c09bb23852aaadfef1863efc08543e6c8673ee2474" },
                { "bn", "b2c3fe68b52548a146a66ad39141bc2bcf19b749525bf71336d11909f4c2228f97e21cb5d6b2453f80aaa021b00ec50d40f6062c50e7aca9e7a7ee4f9527abb7" },
                { "br", "ee70a4c1fdb519e225a2af1a871b82fecfce5606512ce59a1b598f9105f8e6c60e8c927b782f69265e4e3bcc00ab8d1ff1b6540ae87bb85b06c0d51b9e8588c8" },
                { "bs", "3ec7d36d7c77228341cc431d3d9da7befebf17e69fa2ff066caad8e35e2da9b01930ca274083311b20ad509071cd0fad8af81688e5ddf26bd9616c0a4ea9f07f" },
                { "ca", "96376aaed69fcb146facee030353779eabaf244f729dfefc62e544048e870bba6345908e98a30d0c93957b82a8404b69a1dd7be095638f66bc00b79382d92802" },
                { "cak", "42bfef522b38923baf4da71640c7746bd98a1f0bdc70d5618e2681c8d53c53dba3d7a03e47af2138f53a5b5f92ce1be190be276d4a084b2bd8e1ecdd928d495f" },
                { "cs", "330f4510622e87697666602c6feb1364436eab0ec4f8b319a3455ad5dee2ca44ee9ad4476a6c2ab3744c72089d2676626eeea26f3a1f471904ec685fcfab37aa" },
                { "cy", "f99eeb8af358c5201452e8987e6620e2d2148ecf9591fe8438be7f950c543b9bd3762d7112ea1f0696d47da8167818b55257c03283b1a936faf471081a3bf816" },
                { "da", "f780fcdd780a166dafd11524dbbb8f104d934fb55bd6713606558856e4fcc7b4ef5494290bc6402326cf07ee063bd0143f0bf895d0883c977415c39816a4c121" },
                { "de", "f5665d71f6641b22374c80f4085adaff85ddaa04d6acdab6bdb892d9f233ec50619b4c076ae51f925b1eb89ed0b49670c4bff640e62718f1463a912a0615c17c" },
                { "dsb", "17ddf4a25529d2e6ad4efc647d29805d881b222ec15cec16dd6fec05f8cb85b36ae4853f00cc4ad99fbd8ed2a7d14cad798a2ee6e7846a5fba281e0936a65968" },
                { "el", "e189f81996348dc4d557cc2cba60534a95e6a5ce37ec03db14675e35d017445d142e4bf198fc105441e73506d0d7db72ce3cd509b1277a47a48f348b78c31177" },
                { "en-CA", "616f08734d62447788c3af93bf663e37240d087e21a70a38fa3bc2c7ec81f9f3bc87a193caf3a281e7c5560bbcf5f5407ac86cc072633d810c49b4db706908b9" },
                { "en-GB", "e60e275855bc648e0908e075dcaf99fb444846e2cbb46711cb2cb50191399355d20e659cb184c286aac01614759f084b106f955a19487cbfb6001c3bd3ea7c35" },
                { "en-US", "1fb03bfd017a59f28fda120fcb5ea18c2508dc428a0633128fc81232808a332d4a4397a8a924c69d88ac1e886c04660b648a29b54c586ea10ffd7d042de8fe95" },
                { "eo", "0133c26bb372f01377dba4dc0e926260ae5285770a03af8ca444c1aad26497ee718f95c12f7f4bd02a40a5e73e58f6e2d511bff21561a364776441f69224160e" },
                { "es-AR", "d3d229a9071d54c8527e560966c239110cf4b90b9b589717cb97fecd3558ed6d6d5158eff2f05086fc92a5f732550f5a2873861e44b94f21f1f31f0b04a1afd0" },
                { "es-CL", "8bfa6974ae14e15e7507bc5258425692cff1b7b1d29775c232ff165bc17aa0913d08a71bf94701f45235c0f1b9cb0389fb1651102318e72d0153659dc0605d73" },
                { "es-ES", "6b97da80566feacc5384854f9e990ee00ac341fb94b19b05d47587895ad0b94e31de40c45ee4eb036fd7c8f485d0873bb8867fa4bd176189f9b2b91a8a07e774" },
                { "es-MX", "8d3dc01db9af7967866c348748cca77bf775e570524f0d474a87f29fdb37eb43180db196d77b1078490fee0be7d8c9b2ae2be81445727315c70f9935bef357a4" },
                { "et", "dafa1c367c4659001c8647006c5447cde00fb0a2dd0548245feb5c597c271432e44dc81ee8e7a31e6ea7caef7f50e2b16b51b19454a9a5f0a7dd896a05f6aa07" },
                { "eu", "72006807aa73fc9ecc059b123d1da042609517795c5e806a632da65b1126ca58bbcf2a33f5fe1ce6cf27ec9408511add47e5d9b7ea493640b9b43d54794f24a2" },
                { "fa", "840ecf5bb2907a4b4e40549218b4934cff7ef27baef98fa10ea9e954ea42028e17e7daba4dfaf454373f91b3e8599bab3cc7325dd88157429da716e312befa0d" },
                { "ff", "f4782c53bfcab9b93bf7f31242e5671da82a10dca5ab907a460bd4e207b1631e1167b7a12fa60db8d1062ea092f1726aeb1be34f11174f1c97d83bf2e9db8429" },
                { "fi", "9b424c51574742621fdefb3fc993dca823b97f78506235a8825d4fa5c53e049638ccfd509aa141835d86e54613e825acd1146d6403feeb085111c4c2c2a3effd" },
                { "fr", "f1366722087b438f44ec227a564a90852638788c6314956512cfa56a25e9c332904d7a535f13f1bf614534b60d6eae59469e6266a05da88bb60738d057a99c4a" },
                { "fur", "4c92e55042cf1c2f8593694578e2a91f49ff03d4d665b36941b6e51fb17a49eedd1a5a8820f5c8acff9ea5463eda1fd0a0f289b21de39d6928dd5bcf3192157e" },
                { "fy-NL", "912b8134cfa82056f6ca9c7f0f7d48cc61c5bbb059040f57f4ed455525a49da224f3484641da824e3bc58c8d4e5ddf1869de4d6135b2cdd3541efc06a35a2b44" },
                { "ga-IE", "254ecbd6bca12d98f20cc314ed21f8302c31cc7c7c37d3d0f35d78042365ba9e2c43f0dcae2c6ca3fa02499ae08af4bf6c52eabfb654702c9aa3ed8aa9cfaf27" },
                { "gd", "220a1306a8ec582a68269f2c65dd6c60818448938501fd20e5575509f6f65f8299dcc386384715a98e8dde1a6dae0af1075c223d4b57e1b8738fa28a04cdbd93" },
                { "gl", "0e09ad8d730a8ae694d985e71412eeafb608d3e69ca8f33f9fd787040be94fd01c380eb5009ddaafa1a4c9d31e677b285ccac4440808a1825872abbe3618b20d" },
                { "gn", "2222616f427bfb48ec54b0aeaf2b588dce016a1cfde32857e6fb96d5add6f13790ad8b3eb96fab344cfc0ab30d9bb8bc70ca6fda7a2621a14c5fdbad9c0b6e7b" },
                { "gu-IN", "ff06a2e76f6d0368d0dd0923bce62a86889970ef5a2d62550b49c8851e3267b36e246a355dc491fb14f2cb4eba386182d0737a737d56e731cb8b38100d50c5f2" },
                { "he", "02f20bcc1926d0238605d846a93d4f62d6b32f75a2fb380e23eb97368c1de45c051a7e87fc2dd6acc1ee3d9af99616c539119d73b51c9595b213d2902d3099b0" },
                { "hi-IN", "f56cb4a050ed1e3743de793ddbd1e087ad552129035d3f78946c9e107404bd62fc728093b108ee189117d13026a61591febef38f544546a52062b48522ccfda3" },
                { "hr", "e6143c4bbf21b7164ac96f167c0cc130c44b65abe4d8becb5a829bb4063bf5a8556d765bcbe29ee994442bd6bf77a5a18274a9beb7f238c1ef202523a8df881a" },
                { "hsb", "48ee76760642c223a38b9b4d009dfd8474b2663741f320ea0b638986699ed4d82006a3fe6ea38b32148da87ae9fb2e43509d7c39b90b5f96d1d77ffdb3aec85b" },
                { "hu", "4a98e140c478d29827de86e394491b3f26a86e580017410fff6c3f437181f073b7903f082ebafe30238ccae4b8a13300977c7ad9de55001917ea6500c0058f26" },
                { "hy-AM", "c52d5fd1705e1b5907cadcf9d40a45947bc19bada65c28e439d3953ce406c1cf0f371802df1daafe40c4a7d2551fe7a7662eb4778c753897f7b4abe90ea223b6" },
                { "ia", "d0b081f60f8e18293624263a10a07d179bd3eb4a8f19ab19c86d2966e8563ad53ac24604873e08ffcbf3e8280f9ac9bac8fc5d9b71b9e491ce27dffd9405ec10" },
                { "id", "4267cc77f30e039778feee951cdb05015c818488b81c3b6da99498984cd1fddd734a89627a627fc8553b5d3a0cc9cd564fcb4e93e5e123dac1c9693f85f8f0d1" },
                { "is", "4907ee5216784d4b98bc4e26fa7a558dc1bb759763607b6074a9415918b0d7aaf085e29710bfd08d0bd343fb6510a1d1a86c8f35099f770711a636a7d222b595" },
                { "it", "2b4e047d9bc0c88116b0b8e77a905acdbab35fe7bb1b0e08d357066960fdaeea8d6eade61c39d043446d97d7ca88af629bc4bb19ddb76cf3ed631a07376b6e01" },
                { "ja", "7e284ccceea346070240326aed24b0f816df5b34611aef79556d64ec6f83e4f303b07b96e92288cec05a0ce7f2b374dfbb8b6ea0c0beba527b7f14705e9bd3bc" },
                { "ka", "5a8d99507e8a0e15966c27b58ff51ac2075ac3cd95d3dd622e532a4a93b4f9191f30300ab424a256cc1978648cf4436ebfb35a15e0be136eb6af7a2d0257d796" },
                { "kab", "da55aac65e7d6f29d3acb4d17efe01ac9900444b4ae9738b9ba1b508f76abf2cfd09b8ba7065d75ed34fca55811f560b74dc6a42172924896c8525a84669db90" },
                { "kk", "e4091d0238d862864f0cbed11734ddb3d5072e07f21467bf4f72674ed998c1abbeaa2b067ad8317ae3a697d1a8a3cf0dc991408bd2ef8eb11a3604c5885f775d" },
                { "km", "fefb705067028698d7b2a2d0d8f7e27c0967bc210ad023ec4cf67ca9d38f0422de01e19dac55df313a8f864ad5bd54d0a7e92c9bd96cdd345cde450b495e12b7" },
                { "kn", "7b3b08c2df6041104f182d790f120ed805e3744e55dec6009fab3d8a28b8551a07c1ca24c09001925349022afcdd6b9d7b67676dadbf091615b13d076bad2e60" },
                { "ko", "bab6fbba4bf79941cfab26099d459487b659d3111d0dd0a8ebeec5dafea8ae3f958a0c82499dbe5e96de13032a91ff5ac67ff95e0d9904a5a496d64b043fc6f1" },
                { "lij", "0bbceb7d4e7a7a9854fdf0848be8aa98a996051476e88651e0cb469b79ef6c3e92e83603b4e91244960fcfcf6ee496ead07acc73d933d0e5c7647967660695f3" },
                { "lt", "dc7f359601d9a104bb28ec4276e0d80928e8d277d778c232ae96c703945fe2b04571972754679ff205768a671c0ff454d3da10f0e91bc182bcf10954bb29fe60" },
                { "lv", "2ff93502ac92dfff08e78705d4e88bea8f369eff1ed28faf6197fdfaa5de1359232e978deaced6d048d6d60073ec885a6e884d0ee6d3336a4de32e06e1a35f49" },
                { "mk", "ceca9bf7bc34986ce9792a7c80e21ec6e0659417d1e458d24cfac7faaa90f74e5e463d9f9e6425ff02bd23fdd1afb27340d4b6c8c1f12aa82bec001cc0f63ae4" },
                { "mr", "71bd85a55b221758e07d78bb9f11ffc6b2641514b560bfd2c7f6ad6a1e5eee25bba03538460567f9e0036357da4a87729aadccaf80824eaef0ca78c967d2b71f" },
                { "ms", "5f70cf387bd93693f1f21c6a78e9edf76be45508fc7fc4538ea24d184fcffc74d908f5bdf2ffd1642ebc3a45de3e0aac37183f96cbd575df96744e80fd5a9919" },
                { "my", "6b16818bb4bf04ef4623a0cc0456a52b4cf1f8d1ad669406d91dcb7560c68be7735c47da2a7c1011896ce4d8ee4a9ca788927d26994390ea39cac21093c41b0c" },
                { "nb-NO", "415a85d7562a04951e39a5f2c1f97aa7f6ca2696aa94c61daa54c4f85d9888cb7bc704a2159e231eaba702c9e4703285bf92b2b99199f0bcb9666aed4dfc1fde" },
                { "ne-NP", "f1c70ec50bc8c422c0bb25dd68df652b3034d798568ccec7337fdc8213a559bb598ae2c0125fab364087173c1a179f4855379ef579fafb555324c0779c182544" },
                { "nl", "44207c1e6b7d847d35e54b4bcc21f7ff7ba2c01708c7a0ec7319d30e103bf5aea8df9ad7b79d0f1210e22906d1feb8c29ebb00ab7018e61904b4eb64a1c18037" },
                { "nn-NO", "9131356fe1b64cbe1965e89cf4d2955e1e597b300e7acae465190d5747cd16eaa40f1c980852448a6518f8e167b4bea037148e2c956b2a65b881d9e1e56772bd" },
                { "oc", "ab141afbfdaad90bc954c4221d1637e7688e9cf2bceffc854bec380ca8b97d0621ffeccefc41c1e004ece3ebf48e5035cf7e5ccf778498369b1713cb28785b8d" },
                { "pa-IN", "aeefc4dcb98fd6eb8a4bd3cd8b3d15bf7b608950c7d63b026ca49e9423fd4e5ddde437330f2b46df5b4d91dee10502d4721e29feb9c8cd0814038baf0785161a" },
                { "pl", "f14377dee32247046da0c184252aac5fa8c709bb0812a595e00e47da78f061ed6eabec5ef95e5ff9e1f3a8ca8d3f7db558fa87e200fd5c9ded5e6e9e982ae8d0" },
                { "pt-BR", "a160cde454e430e6cc3ab824ff3c9245a4a96cf671b2c982531b9c05b4e971016e60506fa8ca7f7a80fe26b28d3266863d7b3a9c971947eac7762818c04d60e0" },
                { "pt-PT", "269b759ad52a30b481ad0575a521883f6df2a8511616d09d4cc4399fe177286c8f6a778f5cabf8894a5bb8635da40df55a89b9e0dece13bfc69f5007c599470e" },
                { "rm", "d9d51978f490934cf85d9668d2d7816227de8c502192cd08002085e24a7357f84be8179920fb27a39063f73916b5ac524235f49e80a705cc3a5a05db288ebaa8" },
                { "ro", "ee1cce8c21014436094d392a862db3b42430cf2a21998e77b96d685ed6d7812323d0b11c09e36f6294cbf53351ff1002221c52db299c11281ca8798e7950f35b" },
                { "ru", "87854593c09f01748dcbba19decbca3e7c54b6861d316b3315ae12e8e4b49c52c756333ae8fd3ac49c615667d446417e0a8e05290955669b52c657e6a9a7b271" },
                { "sat", "da265db360a745781aaf307e0a6b9c20f493c187f31f4b6c24e26ecf5860cbc004300e2681a8fd60c0c8234b52a856859a9ea43f8dc7073850ff67a03ea1c1af" },
                { "sc", "a0f316250a0a349eb93d5b84138eae64ee79d1183eaa3b4300304c29542bad0975080f2ff208ff9e70e0fd92aabe73930a9aec8b00bd3e9c1debd7bb4fac4df5" },
                { "sco", "dd34c7a58087c740b2f4689e6b61edc48e4dd431d50efe1445b479ce96726be31b631990c141540e8e7f5472f915513fbe32e7b6216c7fec34fd5837d51cd676" },
                { "si", "caf5e1413452d94f086fff525545f2ea99d62d55ded68be1f3a65261d021a9443d932d9913e15f643c1603660342cc06506b1ba4faa0aadd9dd1a92e00d025bc" },
                { "sk", "56e3686875cdd27cb841c5f89677076f56f1eeae22a48772cbdacd5566bd56bdff3eb1c6e86d21c8b9215564b376df9a89f9e1a0721af5eb21fd6010242f6621" },
                { "skr", "c643f33123dec4705f741314192240b7cda1873289d5f93ce05b6fc327033fafcfdccadb2898d2564aa2ee6e16cdb47b407cc9bcc3a681146562f5bc2ab9f1e7" },
                { "sl", "acbd4cd8f06d4c9a7df11362f9af11da67afdbdd593dc30c5f8ab40d3d8a2a6b3059a63b0e817301f9a67f5f0c0e00766a90eea5960e1ca196f1a7c9c48f1f50" },
                { "son", "030fe18e848b1f2bbd3a7d46234b6fb6ad91a116ca68bb97b48a9db98146ed5b9d4a1f89623d791489abd797fc83d7ff01f38b05dd277da83d8cf80df68d9065" },
                { "sq", "e4d59b49d8074815d1f807369adacfe31771f70dc6ac67141f3444a0b85aa6a196111453c766aa7c631c4bf8e4ff19ab77f4570ee141e85f9bac77452085f4db" },
                { "sr", "7a1eb45ce2b3e3c9638741ae236898d8fc83873365df5d7c0240c354d627cbba8bb38ad4c1fa730d0a2be9c4006793a9d88bce0fc76f2a4c1a2afd404cdc85d9" },
                { "sv-SE", "cd82249d912dd5cfaec3d9b4fce3e4607e1735de4855f591e6c779f2b88ccb5d5ab912f2818e58bbc6049427ac5624b19bdf42d34e33a6d1a553805ab27d96b6" },
                { "szl", "c24aad2a5494fbd4dd9135ceda51005b5a2ca830b302f85ecd9f4d65ce1c5394ebddf70f6a73b3de0a7583ace43cd6e86f3c6d3d0f3666beefeadbf61a1b058d" },
                { "ta", "20a1027bd16d9637f60a1f31e0009ee5cbd7e1014dde25d812d9ef0ea0ba4bdc4265ee795d8077027434586602b794e12b2c9984528c3554e35df31c516b8baa" },
                { "te", "05fb91047ecc2d0a06b4cc05ed0d573330fd544b27bb571aff4ec39547e8b3d5ec8d0e6a2449e78c867af6601a076f1aa4dcb4da93fddcbb0e4b16b95ba9bbac" },
                { "tg", "c093642955f393bc664a7523cd09b42ae565d6f23340c2ae9545e260761b17c0bd28471811aa8284b4def12e4c2c1ffd22063cb4bc60c3a8143f801ab9f41d01" },
                { "th", "515df6949d2536b00ee45ad431a08202f8b75360a56a152037eb61b74ee33790d20778d5154b94636388fa4fb1af18cb54f9771436dab9c7399403f8f104d354" },
                { "tl", "372538ed4e9db9a9cdc3423cc1963d4b40b7f09445fec40358763c9a88d4a9810098d52b897f03b69f1f34817a715c4fbba90b205197d2d915e133b2e6dcc840" },
                { "tr", "ca65bc9aca92283e865e447e1706078a73c347a539ba524dbbe92479864c2da5a4c383610ee85ff5467d03a079bbdecf1eb8a00e2e629d6027ec6ff410638f89" },
                { "trs", "e72c62c65d9c5cbb95c8627b8be293b8aeeea811e1695de306d6a624459d001e153f46f806700133263d3310ec47a551de81d4cb31f320ba3d572cb402cad7d4" },
                { "uk", "effe142844ef112f93139a711543d4c680b2a30f61296b460e945cb586dad64cbd5aafaf2a6df42e0ccc0b85c64dbfaea56c9cfcd3a80ecd191d061ea4223aed" },
                { "ur", "aa6d4586575d2c4aa1311c5a5290f63dcdac1e7c6389619560dedcf8295f34772bb6f67377014a9ea77be81b9c42c1e98a7d29fcc7f0e926b057a92b828b3354" },
                { "uz", "213587d7cc8a2d60aa48fc95e5e893080664cc5aa646767790b7348504298e0ef6a6922c748057e502a80b48840e03aac403f702517d4910cdca7de5749c3320" },
                { "vi", "56ac34b2a68f96b94a703c7fe7bd70c4721be792905cea1c75f5c53eb2c5eca790a74a9ad0ac9cc4943a367cbc695639eb8529965c435c5b222c327f72a60725" },
                { "xh", "c3d5e62bb8e77611b37938735030c6b2c487554eb39c4cbe4ca0659f3f35f71dea10bce6706793ea245d4ddc5a2e2eaff8f28df22ae14938a5ae30b617972514" },
                { "zh-CN", "8c90a8830bedd9076d193fe8e7f83eefdb6c000f60ee379a07264e5cd31e209172fc3185cb3bc8eec1cffa9321e95fb346e3b122f8050447baa23eecbbb1ea86" },
                { "zh-TW", "c9b8fa5e9dbdcddb927a6c0cd474a7e2064ee87029ce9ea92b83ba42b83440393c16f31309a9a9222d28251061fbd27c31d2f5b3f85b54459deba99e2224d559" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.16.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "5d24574971ccb2836cc5a6cb56134f6f1599ba3517aa3c18f019e8ff966ad594c893da217a5036b8fe4ba920741d8415fd5c5d49f82aef7047aa7d0f83f7b2b8" },
                { "af", "428b800847786c58634fb02a0ad28a7af324efa592d44a945a1eb74094c2af20f12e63cc0e3678d413830edc0b1bb21c727117586ddf0baed92db6fbbc6193e0" },
                { "an", "44ef40e9ca9e5ad287e9bb00eabbddc5e752172b1ba6d3ce6962178623a4a848f005823e85d2aada63ed137cd80b001c4248dac3e6de7aa1d907c4f89e6160f5" },
                { "ar", "30993c60fa2bff27112e122efdaa645b40a432cf38b64f564c415238880569ddb13c663bddba90cf72447d43d5a5e21b882695cd42fc94e2aa2bbfca0440f72a" },
                { "ast", "5cf73c70c20b9479882a547cf0f63b41e21150275954baf0f0f61f993e19297a31cc381757df6119f2053916cf101026b7e5ae9aff02a221cce092364c6f7012" },
                { "az", "40a5e3aca3f47771cea033329275af5ffa2fa77ddd5f61fafed4bac6f6d5dd34b5f2c64bcc22887ac89f3afc871c68d2388fc1a15de5e1d169fe8a3540b9ecfd" },
                { "be", "1ae1552edddcb5b1275e18096c7cfe46b9c65ca8585cb783dc818b30c27d9d73bfc13e0c8cc18a73801179320cdb28b0b295b73863e110dbde8e81bc5626573b" },
                { "bg", "eb3f5cee957b67e4e189b3713527cfda305e64e20ffba30f2c29598a10e62d4b0541e8e5624cd261ba3ab50e8e8733ead3f775cd262cab0298a0e2d73b226708" },
                { "bn", "4fb1d80837b71205e251440591c08761df14719f8a9ba49d046451e161a647982ec301c0fc3e5478cbbcba1970c3d402a282a221c1e59f462ca1549da46b16c3" },
                { "br", "4dfd68aedfa74fa302e997052b5723516029ca872735308b9f61bbd2c9f63bd11f48f05e5ae7f9c211d4ee7eb3b5afa33daf543880d38cf93e46a037de691ed0" },
                { "bs", "2a55488abf6363464831bc723d3d39e9a0a8c4b72d8446f076a07e01e62b8c1066874eca4f18a59c3e2175110cfdebc5d8458116bfecad6df54fb951c6c48656" },
                { "ca", "a40f0effa0a569dee7fb4848938f972dfe528a2ac87093fc022318fe6a848f5ccb611ab8d33b08fd924eed0f1e6ebdc024f1464abcabe9c089fd1e6b0387f0a0" },
                { "cak", "894b4c7fa9511c481ebba04a73b1b75a4d97e146936baf348adc186911d5bfab7098c557b71d864966c6a19a974009d922682b7ebb8ce0bc6d2345639a5c0e71" },
                { "cs", "84cf93492123010f37fcff0a1a435cb7eb424426275d21403fee8e9c929d4d63d2c1a944298c1da426eb9755661ceef9d56642f1c161d1c94d601062585704aa" },
                { "cy", "020c35baa4ab653676f232ef2028f4b7fce6ba5208f31f25e2bdc1b2f6062e419870a9d8302f67fd83bdd10486c0779e2e1f8bfd33702cd673b0aaed2343f16f" },
                { "da", "d13d563ee4c20d18d2b9fe9348d99d7d4aff6c2ad423e1f75d2b632c91b2a925e29f4fe297b33b01ce280a5975e59f6c4f230bfeb74605faed41e609afd282fa" },
                { "de", "7e43672969f6db6dcc2f3ce5789dd923800f4e436bd80637476933e5d68b3cb5fae2e7e276bf53ff8186dc318ffd187354a39f7387f86b7249641edbe6798db8" },
                { "dsb", "3f03ed0949d384cfb105063ff6bcbee8148a07e76826c607f984aa57f31bc3119f3c8d7765f6ced014edf84c841e8b18cba1c893c2684605ec2b9d654aad8ad3" },
                { "el", "97270f6644098503445d55869848e087390eeb089d1d4dafeff1569fc8647cc913e8ee8f8fb7b38be08e0b217d93357082bd6b51427f0b3cc4e21bde7bc8f949" },
                { "en-CA", "e37aa3e54681d28ed44f1e8977d1350947abae627046b26568ae026ed3e37f014d7d95ec6ca44328dcd74ddc919274a1c8dddc84d9f1be21d5578658f9131d76" },
                { "en-GB", "afe35c99d1548bc585556a0a815c1e83dd66115b59d05ffedf05f15b9780784a0c387ff68eb350f97a948599643721f5819f8a2862445540e7b6ac0936605574" },
                { "en-US", "55a33a0ea88954d4fc14b779f525cf3c146a4daf8acff483c662c2990506d0bd7e9ee2fda220e5d4d58bf41359de22d7bd6adbe2c2a4536eee8428a554e0722d" },
                { "eo", "68ceb9a6c093244bcf97b5d513d572d5ce59e45f86fe5a142fede9b930951ef364a24d8e914b8a57975d3d974ab7a48f0fdf6f2e0662fd8b1535566332b26311" },
                { "es-AR", "0c18b3d6be74262a5ffdf0d5cf5a9967382e0b0e718973d5d22fd7316100f2e2d018d9c38a6c6a311c3e716c5c99f59a61b992a7f116997836ea6869e437292b" },
                { "es-CL", "7b7aa66b5d627dcc7e725640d66d87af511e6a8413ca711bebeb6179fb246fc2049efbef2208678acd058c5ed47eed2bbf80be412eb9bef354778485be0708db" },
                { "es-ES", "b8873af138db45eeeb1c4ec5b34a813a33da5d27b231a802afdc414bff3fb17070c783d0c08923f95ea4db50ef5f0c08a7adebc7a8c4d89fdc0eab9b486be771" },
                { "es-MX", "ff795a6ea04677024eed6577a995b3c9435420e01e85ae1d7e1acceb7c6817808032da39c532432d88b2e497175aec4f68f79c59b02ffe700670d4c8687499b8" },
                { "et", "87c738c5644a31503c4cbbcd3d3e491b0772797509e204811ededd5765c427d81e3db0866e3d07670ff1f9066f4f69f420f2165d023e5aa025639ef0284863b7" },
                { "eu", "a495ab40e168b8326fba3b23672f4f3c8271187866d36eb5bf3d42108fb8b34bea9fd4ab3bbd9590252251c4e7300c4d22f5e377e0f59b569185b87dab024c23" },
                { "fa", "709c383bcc611e7dbabd7feb6dd62621271c2e2e06a6951da146dfc1c7c5d396283eef8460707656b7a0ed5fa2e42a8fd44106724f6de50c4682f02dbb82bd3c" },
                { "ff", "90a7c10133cc6538e9c7bb34a5e1710d6b15fb7fd639b83a9b55e926b31c81b01c25142cb05ba9f0c5b63b45af668b2e271acd4a4ae30903e89907d90e17b361" },
                { "fi", "5828c88736d466a077a42b32d82924cf95216605f5cc4bb94c20d9babb13add703871fe54badfeb740741f03c6ea50b0fac74ff8063a5c61740994c383d1a789" },
                { "fr", "2892ce1852d3dd4fef7c2666a63174e39b0ed9aaa15e8d0d7d3b18c745cf1b864b44456e1e1856ab534d8efb995798096624676620558b6e53e20819fb45b361" },
                { "fur", "72bd9fd6e4cae7d44f5f88aff7fcae5e4c9d3954e5e24338be78ddc3e5e74e730291e1236e1f14c903e0d94cabf861e61278cbf1d12cabc0d1c4fcb8d13e4fd0" },
                { "fy-NL", "a5bac461a74c27500a183588b5c692572fb2a39b600a2e3fa32d2995c242095bddd507aa7868887d14c1abbefdc36b3b4554a632d3766979e9ac729a71f5f887" },
                { "ga-IE", "1d2d7bff47ce5edd66a6c32e0c7ede98f63dc058b030e715f9e7ebbe54c4fc7bbb3ed42656aeb2271d25bb7b54bccf9213f2a27a7e7315c376801fa1278d030e" },
                { "gd", "fb91b964281925a927d4abc18f348f7385906912371bc0c31a5fbe8ad6ca48f0ed7341bec10a40a52e3bdef75d37887c258b16a9a72f5eb403f7c5e70a8d4381" },
                { "gl", "2fe741e814be72942facf2b1ef87774dd052d7f58c45faac43c065f02a71fe472cb90aaed665403eecad67ccbddb681a418353e851ba1069e2bd22e823c2472e" },
                { "gn", "eff742847ab56299bffaea0ec769122a851b4fa02b64959ec343ef3df607e26005282b9337b11002730a2c4aced59187bc88afbe8b99e7b3c570bcb1bf4209ac" },
                { "gu-IN", "23fda633fd5bd088f1e0f30351608f6e8e248a8e972d0fa2b4a81a522d8c5edff2668ebe9f96bc830ea92a62ff15ca66c2348fc90265d4fedea011b26cc67199" },
                { "he", "130b63a18f8d66e817ccd09c4b9c67955557df67caf57638a2961034df7d508e2a132c2101c0dce387d53d12dc55975623ba30983a39e2be7b06ab9b79a5194b" },
                { "hi-IN", "146e962b6e50724a90227e6555708bdbf22d650019416b25675174383bd47978aa5d410d5fc02fca6452bc7dd24afdcfa6bb60215cb61fca7599e49338a6d7bc" },
                { "hr", "7a535837906b89cfdfb43f5bf9e4e3277c9846e854385c82dd02a2beb07815862412c7dc3970a7d2a47b7585a1d2604034fc046e412c3b24c3a9773c14ca17c2" },
                { "hsb", "72ee5d51d0edf57e488db33bc431e1a7c77a1b1adcb17ac9b2969c117a1779a37f271cd9b996098f7ac510e2bc54f0a3ae3a736d8930617228f4823f0ba15876" },
                { "hu", "c327f5b90f7bcceb300acd5afb3b04676e0e7c847a04f4d12528f5e7b887a4f069a33709de6de1115d3d70ccbbc89a820c138e5e6b89d117455147a6ab22ec83" },
                { "hy-AM", "358156d830ee8102596a53d291e96f6f0c83643037b7cba070111d182f74cebbf0fcba1479542fc2738b3bb9e74d8fe7cd641b9d408ee35fcb61f96c5d83dc65" },
                { "ia", "8af281743e12899140a9c8ff1683bb32f31c7e108d2bcffef85904f4f3bdb5ce73606e684627c7da997b40c1d6af2154d85fbdca4e669ea831fec2d9a69b6502" },
                { "id", "2659adb994dd4ad9bf091a1b385f862bdcb58ea4cea5a5b8817e215e1e5dddc711d73476584a690715cdca3cdd758ec917a3bafdbf8013c3767ac2e995be4eea" },
                { "is", "d6b5a02fc3d0380ab421c062f52cb8554a40678238343a2868858facf0de4f3d37ce84a8f9cba58357911760f1e932a39053c544fe5fa873049953062c75204f" },
                { "it", "34dd098a2999c886b91d1a50c4fb47707ecb685e5eb279fe16b138f5c97ad33661780d3b0c2b640d0ae5cb7d35ea692ca827053d675cc2629635cbdcae0329f7" },
                { "ja", "4ab774e7cc7973874fc1694d8f8a1a1aed561da925c445b28ff4290bb2ad818d0e280f99dc25861141b003a5356dfd2c2cca0d10b85ebe839774337a767131b9" },
                { "ka", "474b8b3daf2346ac9c1ef407715b5ef20c7e23d49468006df177c9a55a13610c6e4ca6cf356d9f76d86ff64394f8fde96c360a341beea038a7471c97c5a118e2" },
                { "kab", "065d901068a0742e0087c205d3404618e1fef72cc178a13aa88cb4b9b73211164526ce53179fde35e2a9be3d69432be2418e7396caa97457fca20b0c0dc75084" },
                { "kk", "1b3c15e5a0177cfa0e3b62047e7e4d4ea9c20229bcc4da6930b277e0ce687b9d4fed3cca15aff19b3b0124a185125a794cad8a92b9d91446f2cf328fc94248c8" },
                { "km", "edd623f941a95f1f0b636598750ccc5e07e649931e390aa193312cff74a83f5a0c158238644bd04224c127a90d497df362a71740081d65cb75089ab9b79dbc22" },
                { "kn", "9b0853eda020665185c5f0f2068f75711f62ef35149dee7b4c4d4a37c5b1ebe2b249ff654e08133f1406942143975a89949b2758c2f00b7d36dbf1d208670a80" },
                { "ko", "4de815cb930e5bb7cea3e2c14b32b720e3c4335e1ba821db3611b82e0f9d402621aac2cc826cb0738d535f8527d7d99c6f54b332e213e634b481b36d6dc28fce" },
                { "lij", "a87fe819038fc287e37491d4a8b9a89d83b134dca3cd5b46eb13807caadc5f9cd494ed2924a7f7099cfa0c00803f5192db11713dfd9e7c1dcb011ca39676a0dd" },
                { "lt", "7bfb3e08db75804f7eee3d24962aab3a441d7462e2d7bf4ca46fde2390868088dc6a885c30468ec6c268621028b95bc4229306270cfa46a279268ea24cc0f0ce" },
                { "lv", "18419c975402d73bb81a302c3c42792e2b0ba276e154cbf3f5f6fad90a2e4858dd66ecceab0d8c1c3711bbce0ddc8d2e49e84a9a8728b9bd0b452d787c4263b0" },
                { "mk", "b91a9dda24380e6f6410fc17d14b83bf5803f1200d262e944cd94ab371115a8a3b8e129e385a5b9e19511b84f7e265564a22790019205bb4618b776112875aa9" },
                { "mr", "777ce0bd1df1dd132780cb350d093608c7a776e65d19f090ce2e057c2bb6cb54c6df85be33c0d824cddecd84957e3ffd178b668127b9e8ee2d4768c575a7ba3d" },
                { "ms", "c16887c56f3929188e93a97cf62130263c762f0bd39193a3ebe784fef1a3079e1f26403696f1e643bfe9eb62f22676decdc63ec4c618ec5c17814c971a113a93" },
                { "my", "78935e69e12f5ff44fd8b2d559381f88bdb81b7e9e38892a11d1c5c0ac4579ee1b91e7f06648ee0c466acc11ef0d5ce378a6d81adcb33a5743161a26cd4e1f8d" },
                { "nb-NO", "d7c8b2d4607a40ac27dc62f6dc834916a5327e37f8d556e3a5d017d34ad09eeabf6e6174d803fdcf1eb8598608d5f405f994f33cc5a2fbc12d67a994a1440dcb" },
                { "ne-NP", "f48c9ff27b9acaa71349d577b092bce8d70cd4832655454dc3bf7b8ef9884db0a2b0c9e94df44fb80bb74289a0a99aae178dfdef0e86ca867594521bc83ac84f" },
                { "nl", "ff9485d56d7fce633012579332e77b15c59d37d01fddd1e61476cc61ca8dd2b6e84f167152a68ebcffb869b2d2a55548e2e9a07dd4c52bd676d7df4d79038f41" },
                { "nn-NO", "9814732816946cbfd4dc8fa5d720cc351fb4b8396afdb1084b9b39d65a77fd568c69875fa1a3c58134273e6dc698c949dfd83fa9f213681e0de2fb659a809eaa" },
                { "oc", "fe99e65012a8d5880c8bc2cf7ddf5db399fc6088edce559ccb46c99ee5b6638c486bdbf5bc3d2413a735922a9260cbf78f895bd699d3dbf27d3b15032652073d" },
                { "pa-IN", "90bb33486229b8a13ad5a972ebbdcbf0ee9646d7a7e7e24dc33d091462ad442babefdf2e8b5501e6d1a3f31e19c1a7e5e8f64db535978d12af0085b80826ae04" },
                { "pl", "312fca6f8ad64f76dd2ad4db889ab60671fa6e2d909e114201cb59f48efad9d169b5f05ab73012ee54cb5bc290b884e88c363e13cf058803f9d9d2b0eb5d9745" },
                { "pt-BR", "de9f9e832f85250b5ef44e0ae8f99fc2ae55e7f24cfa5537904a39df5e69e207f3bad2bbd73e88da99762c1086211dae6f766a236196f9b6b7115cdfeb4ca345" },
                { "pt-PT", "c85e9eba04297e057c636b1031c6ba7fb645ae0031110d8b71b9e77589178f35e95edef3e8c9dda88a4943b43c53b77a59a68e96a060f1194ccbc573d456e2b1" },
                { "rm", "74dd8a364be2ed36c609133a168dc3dbbdbf3702657a1f80dcb9e226ebbe061f63455b17ac39abdf44aa1bf66b3a68f6bddd2ac2b6de6ca3758188af64b0e8b8" },
                { "ro", "f9221a66b701e7e65c97b3168e59537943cd5f54a9fa5decb5dd92b14a9eded523697a397ea8b020e63f18985d8acfad73d98f46b1d75c716dabe5ca748f2a1d" },
                { "ru", "73b57dd520906b8e4e72849eec5e300cf1f1f07f1ede8479a207908d672c631727c2131c5945ba3e758eac83531fd133e1e4cc3c14b188afe1cb267f974d4155" },
                { "sat", "90fcb7cdfc685531815e6859883f7aecdcb7811691c1d8b3cc94e48a0b50fbfd96c2991135f7ed0e40f3d3b4d7eb92e6f563824d942dfaac5cbcb2f01b1d43f2" },
                { "sc", "2efbb313b2d03351ea07d8c9239a6d8c4bb4dd4e6890ebd716578c0455c6d313e1ede064b31991ca5274cf8133c6479db01e49dd9ec90b4aa6c6cf24e22222d3" },
                { "sco", "a9b6c04351e169b2482db9df71cfddaadb3005634a1d7369307e1b1d879fa9585698a7986b7abb670ce6c0391ec29d269e0a743983e1c7962f5937e5fe0037d1" },
                { "si", "5c801365c0b6a35dec3f385af48829dadd42ca572f008863718f38b43458fefed050e1a444f7b50c6ab66f6bed5ba09d426ded2f16fbe5a2c3ed046f578f3b25" },
                { "sk", "5e7340e7b9a2ef699b9aaa01713477e6d25b0b44a65e40ee24afb06440a181623ac90b5d054eae1d21b6646f6e2c482a8e9efe737cccf3337d4f748dcdfc8b3d" },
                { "skr", "2435cb1b9f399e636fdd062c28ba1ce5654c658d5624ca54d52c23d1ae58be591ddeb8e4dc8a550acd7fa7fed44e32d2bae9cb242050650aeeb5a37418c89f91" },
                { "sl", "1f8a05ce62d47f6f062076cb68058e64e5db1ed0a3a84b3b0e99df78ab681501780db9c5e7c23a8e9310400f09d1e3879d167c3a4fc05d6ffee6c019a0863663" },
                { "son", "ba265650202c70f7b13467f020e019f87d0a6a4ad3d7c5b4ef504f9f1349902536fcb843037507e5f7d3d38fafb835a33f39861f7670b0ab14b1f1985a24be68" },
                { "sq", "78ec9227de97701b9f16f723428064c9917caa114b126891230b0cefc27faa0e32d71a63ba9ba7ae7cbcef4b053b11da606ce4cfe5b1f8146ada79c055632e3c" },
                { "sr", "99094cf61f0614ec1cb24a9ea6c63aee889d6830cf4409fdad34d397dc8de848e31b80b1bf085fede1f503ca61033885318fdf66bc67c8e2ddbf3ddc593e74e7" },
                { "sv-SE", "69ba319a6a03312c0abdd709feb4d4137eee7b2c4e4046d3b71bc9b907dd1dca8100e8754579cb0a6eb32b848f36cf94b8a254d7c5063a9cdcbe6f74ce850f5d" },
                { "szl", "5bd89eb50de9513ef2c3a98d89b3442c1da8c10eae1b2931b05815f89697eac73e0c237ef22e296462d5e9d9e4a4175e1f34415325f573899eb479eb2ce33913" },
                { "ta", "ac1ae0052590b9dee8b0e451411a7d7f212cbf278e62f00d99930662073faa3fda6c95a940ad7afdb5333e1a7292a75ffca27aced68d901904d9ad2c2372dca1" },
                { "te", "81e4ec882ebb580abd99992e36e53948f5b53f68a5ddae70bbb77a438f3ad7cfc0e59b919daeeb851c4f57ab2296177c24781ca661780c94ea94a4c958ae17e1" },
                { "tg", "e9873ac4ab44515606279880a1324e6c625e559d2315722843a61e1d8a75f825219239f0e3b6b454fc0461842d4eb5be18112746450551af2cb30335dd198c78" },
                { "th", "a66f289cb019ce2f4389702fe9606adf55e9bbef4b5c8ab93e24605b67563101eaf29eb7e6c9d384aa29f9e82c771f1a5c6a84d9e982722e85d0ee33a6ebbb8a" },
                { "tl", "b78edbec79b0aa2798ee579e405d5d9f93d92ae4751d57805ba9c9d710eec2aae0d34714fa3933aa0dc895613921171bd3b0c71596e284f3d56bfae3defd1a05" },
                { "tr", "f9dc1fbf509612372fadfb6c4a214bc0e147e92f9382826f2133633b14226d645f8860912adcad99e7a546dfe156e40a9556d0f3ad76a0678b49c6a753fb5b7b" },
                { "trs", "081d1285bf5eea46d8308e68496d133417a22dce070efc62e9c1b6733ac11b7b877d19a180c5b20a089af60cca6da6420c39e8892cc68e71ca6f5e13778ddea3" },
                { "uk", "363eb78cd65f051168a9cfa52f9626916ed20c8f2202dbaa3fb8788758bd80cf9c6ef43767d7c61631f3c0270d18b2d26077f1a0e89284bb51ad8da3c95e14f1" },
                { "ur", "99ae4c6bc13a1b69eb9eea78d89d2a75837f90ee78b8c896750ccfd79d26a9978156fac24f503c01d2f193425fdbf2f05e027467f4915e3d36113703030e8c67" },
                { "uz", "8a99bf4902a58e9b5b1083aae335b67a5375b1987a39d58248531f0c94db35fdc21f45cde6cc7a5bef48ed93d289d0fe568d02df30942f5e04135ddf2e38299c" },
                { "vi", "2ca1bdc2f8d8f9dbd7b815ed4a774fa917a7a81818c3b8cc84915607b1296298d3794881d8d4d46fa1a6039daa6d4cadb48d71ac9888a7eeaee2b7b72f8a2f63" },
                { "xh", "ea081a0c8091d53f3bb9f25f2a1bfee89db2a76b132495cca495db3333965fe53568f42211fd3c9b2bb59b151a38d60c5b168fc490d194216bdf909330361f07" },
                { "zh-CN", "c5dc01ef9d7e4a397c4d8d9d372fa318fb1b3740d444022deed1b50b688075d3dbca6585c3fa19f88a57090779217a70b08c2e1f981bff3fbf14ee26d2c1397e" },
                { "zh-TW", "ef02a54bd72147fb69aa7a46d9d4be97c3499e0808b071bf0dd1795bdcc91a041d14c36073ccc618933ec9655a43b58369f2ca1fc97da902079c797bd031c6a6" }
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
