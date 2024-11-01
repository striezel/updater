/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
        /// publisher name for signed executables of Firefox Aurora
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "133.0b3";


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
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a6579a74f1c263b4882eb8dec9583ac61c4fa13da6553fb234ef587fee71ef51570b758c07cbcac3b90773d308e35a90ba026ea7630a075fd8f3905931eae76b" },
                { "af", "416c194b07d0cdc127ff76eddc8f175657b6cd4d61c24873f8b1116090090c91c5ed9324c0e22a6bf4a74fbbddc5398ca8ca313e542c1b62d1cd3e537698e2d1" },
                { "an", "9d4821eec206a4d8cf25529c4a7c40c60745c6616fe255464c44ebcaeddf0fbc93e6a4736c2579b4bab0acdd00f600ac620665fc4272380866e608bbb867fd82" },
                { "ar", "ce87340ac4b9cc311faaa534d15245d7a68a7f4cc695a3b9124ad925ab0c6616ad7c1b0911d235ab1dcfe2a3a80a8817c43a3e15e24480490b715181d0d1b9b7" },
                { "ast", "7a45c5abd2d77123ff9d762a03ba54cc23736f40c22b58e0dabd5146efe26ae361746532811ded13dc1f19c13739c301da0928e91b6bfd798966521ee87a7eed" },
                { "az", "6719e475eb0f1c400d7bac411325e8c1ff08c7251184cea3fb7b6f2f0971a3602ade94396fa4bff0237ef2a0ca3d466c35c7a56772e8f5928b8e45a6343e966d" },
                { "be", "2eb600a024d6509bf917de44a1d1d14ad0a5dd85745098f178e995e6ddc3894af2408840e8b50a82ddb399636618174f11fe07b8a5fa07518428ae4fef0e45d4" },
                { "bg", "ac5646c2d743723d49fbbc32ab610a83bd9aaba2461243ca50427f868e0232de0e580d3db5e643259e856df312984c1c4bca79a2f7fd76a39b2f292d3efec4ec" },
                { "bn", "0befdd9c7c6f10ce1696be409506ad0d1659cca2affaaf45334b5b1e675d8de43de041f6b5906b13b39cf2ede113b23c7a3ff0d0ae6109c18aeaa66110b12f53" },
                { "br", "27c66775c7203e602f521a0bc5256d6afaa02d8f2904548f9c853ca88719904973b039ed79da52f088f8fa86c6fce221249627cbfcb729018b728832490cc88f" },
                { "bs", "564d2126f32c85c79bfa9712ac424259cb24ffcb2875c3fb56f555c029c19a243044ec66043ec6cf491fa81168860e4d4c52004efeb5a52237b0b797f6339778" },
                { "ca", "ec57229b906a40d754390fd8650cc7f249121221dcb9de657c5506bef06743d8f3d1d2711fa2674faa1109a0b0f4f1eb1205867599e935cb11eb996917cb1229" },
                { "cak", "f7528d35e967084ba6861132683d8a0017eac21f38da7b3415c48cd3ba36d4aded24296894c3378abb4b0e76f9502e4350abac757762623e913d6edce6ef66c1" },
                { "cs", "09791dc9db1f787678ac31f548114a5258c79d09744dbf5b4bf3ffc050f7b0b48d1a7298d536e11895dd7776d6db48b4365f540243f54120f5a20357e3d0d58d" },
                { "cy", "aaa2fbeb669d7baac50d7cf502af925b18f1cb97c67710d3a491aaecfb4968b72aab66b2c8bfa6dd3be8cb3e07b8b3260a0349bd606029b867d0531550557ab5" },
                { "da", "b15f3b1769791f5348cd9e7f95ccfeb4d2a30a8255b396b827b9777db6ae5169614210d0fb58c8cb3dd3a3ee3b66d4e336b9cbdfb8f0e1ab03c45e299e43fe1e" },
                { "de", "5f9647af365d81240257dd1f077b324221f7f0d19397b0451a9668c140cd8693cdde13d6afd4e535ea4739c6df0e1fbfd730d30030075f945cbdf966f8bff513" },
                { "dsb", "18e53ba89567481ad132f68de71626bf4c3be66b15835b0e83f8119b7f1baa1d917243217b338f0e3c174c82055135a587cb99b63c4d9705d75802bb4f3b0829" },
                { "el", "48ea71bc193e9674200000b96f684d3ad8a6114efa4dc26676bbd77c7c5fec8846c4fd4193299d996bb6616dfcbfca095293e51f57acc9d66b48339da2e87438" },
                { "en-CA", "8be96c7c845f0a1a7cbe22f6ace2a26c8c247de32db5cb41a45546b07dbb804ccf195c5e9854e9aeb117ac46f96dda74e1efc47d839982cc3b4e7fae94b3e041" },
                { "en-GB", "39925c8702a5d3be4c7c2def75090b258b9b195bcccf4b44702b75b3818d69d40c6b7d1e1edd29864c29b8a2429004363a87225c818c149f9821b1280693eaae" },
                { "en-US", "006742cc7b97ff7c8bc4a55bf6bed1c19a0d669057925d256b8de630cc16cea00bd02390da501705bc058a8b430517498c826be0db1ec0fcda9456fe383e12d4" },
                { "eo", "ad13c9e6d3866b8c5dd6ec9bc468c0b0361cf8e72df2fa110a620436c2c5ca3ced8af2ca7f47fb7b334d2c6d1ae19dfd10a891c6738a00baa53054a2dbb8378b" },
                { "es-AR", "7893497bc3f38474cf989ab023d2f409240e870212d6ffb368d8649c72721a1e004c0d223a8e589fac40f1590042d8317b972cdec9c75195e5ebae0ceaef60f6" },
                { "es-CL", "b7f87e7f0f347b2ce5fd130004164bb3ca25fa4bd818a9deac1a5bec943568d9a31ae4b8e8d3ae17bd5df54a4f593924f5489c640936f89685da82a9f48fe93f" },
                { "es-ES", "0cae62f8d8ee45d43da217b92f564ca97ed5c59a09be50853cfd3db20a99e7e675091045ffa9bab4d1e1200602c2ebf9479e7f30e7cb03fd8f64d07751b587dd" },
                { "es-MX", "8dfd2bfc430504fc60b8e00d4fb4b4923d01914161f0c18bd7cf5b3b2030b79361635d39c25bf614de2adef1a9f43c26b906ec0c3e00933638ea89c0a8ebcd87" },
                { "et", "4f888f81e5e12984d053cd6d3bd220596c532d53c9653c40c9c878e3d5636829fa32106586c5b133a5bda58ea98bf3543fe9c986e9954eb4d4f95ad325215b27" },
                { "eu", "793799d2f5a543cac8036f94451c034769d81ee6f988e68b0e800278f4882a097c6431ccda81d59b259815df75755f7f761fccdc524bea0633004efa9febac14" },
                { "fa", "171c6b73c2d81079770764c281f1fca5f1ae3b8365fdee53395f4b442d7a1ed0c5dc70130b57d100103579ae3230f3d96d2781a480f3c2865d85e3388432a302" },
                { "ff", "046e87ad4ad279178767da7d96cf3944e8b3d492dab164cad1606bca9a36965eb10fb744c61e4b6a041848995101f708bb743d498d2dfd7f611dcdb98b73f286" },
                { "fi", "e2808c3d735cdcacf03bf34a3460934a27b7e4494c0547d7f18aa028ea0977b07a56b80d1d607b46346f532c34cd0793b2325c4156a026588aaff34a0c04a39d" },
                { "fr", "052c8e398cc330b3d840bf66815f2af6ede60488c839b399b9e79aac2d3d097ca95602ab6889777b1f1c2b7bf9c37f1cb332642e1933917986d28b9815394bb7" },
                { "fur", "424eb9916bfc3939ac92ec35dfb00462477899242fc092075dac4d76c67083565bda69e6c56babc2c55138774a072efa013d09688d829dd5e1978044c41a3212" },
                { "fy-NL", "c44a26aa36a0a030f848f649f6b8fbdf4564260a8bfcd001a4475bc7a71d644744a74360c422cf87d1e91d56bd8c895b99eafcdc1adc8e2aaa19ac235c3ea0b7" },
                { "ga-IE", "e3ba1b80cd1b740ef44fa69f23af42b8604419c43f0bb9733cba7826139392751a7321711510e8b34b4508725bd991456890831204ae6145d0aa097f283ad2f6" },
                { "gd", "c0c8622fd6f2220fe4f9df767e443c0de3120741a89b055441e3bc318cd8ae0784e00b0b8dc497b21dd36df9b6e2e929d16813fd9b2f9a0df278f0237400dd47" },
                { "gl", "6176018ec46f6b7971495414902f960c140a568e9f561bce7419b217395478a30baec90e717ee73c1124c5b85b58dff7bf6bfa7051c96463935e3dc92723fd58" },
                { "gn", "fcbe7212ac8de01941671bedb11dfc83ad43c1e92f1ad12a7445a133a87738dc426f2062ce7d233a64ff2dcf2d2c96965130a368d41d049641adcb4262be004d" },
                { "gu-IN", "9cf0c086c574ae004eda13b3cad10914e98a7b05325d509aa3609906b31a9376eec0705718a7207cace03ae8022775530bc7282e128f56da939ab128bb680db1" },
                { "he", "8e3859dbbdd1151c17ba2ffa71b5f54067f02c311e5adc0257b989b3cacabc28a94bba47196bf1980042ea226662bdf997732c638217c66640bab22ba4392712" },
                { "hi-IN", "5221f863fb694c33aa55633f50746560d9f471b2579b8295e4840e8ec40c1de179e472ea3fb4c037543a2b7ecbf5152b2e4ed22861069b2074bf8a31f0840bd7" },
                { "hr", "961a43ebaf4f0e238ea3080f40b260f06d39b68a5d2e0cf60a1b3b759db3c799b7e0427e8ad33cc1829406adc2816fff87f05b2f2736cda4838c8d2162e5da15" },
                { "hsb", "ef1cfa88082b12b67a4cb6ed9d6395ec0c376ebc0f7ca059d855c081ae2402389afe878b401fab40c29d5d43f599951cc7beab51b37705360c857c42c35b7a7d" },
                { "hu", "7b3644fecf1b93f24db40a7f24fab85241e7d76f3fe47e3efd5382317c7ed9db4959d9413eaf8f0e9d26f196db3a3296c382c25d244085cbb6a4f4b17403af0c" },
                { "hy-AM", "5517e3e8caf06169d90aa62af21f5563a5ee8e92a0226f239946380a05f7ae302078e9815b6ae9128f108d23fec240bd2d36f1552484708a76bce69821c1e7ff" },
                { "ia", "5b196745f5a4388c5bae6101dcb9b51eaefd42242af5cc4fd4698110065d0507561f353d4d1ee2bfda72b4c96bc5037807ae17b917d63e3cb2fee16ca481e67a" },
                { "id", "2cc34700ca48ed77dbd1d93c61bb1398e7ea08a5aee3a9c248315b86f6336c5a88f2c71bd71f2160f692aae03b3f8e1353db00c664e99d614de2be44a2ad0132" },
                { "is", "3ad6e8fb5f63d49f6619867a3e11ba0d739df74effbe771f901dc78effd5ea48fb5299adcbf708d3e2fb7a4fc6c85d0002bc25f48961b6ad2fc045372bc5f581" },
                { "it", "6d676798a19dcbfc73a8d4e552f210346a1c82f7e842be9c3b95b0bc04d66601afabee8b1433134cb6be7ac80961e81eb7fc42b822b9afa99a0d4be1ad60b5a7" },
                { "ja", "ef3f28ca5f3e1af8d2de39d7ce27275d0f0d40608eba49d37081044e1864cb6457352d4965319f0d73a3cb11eef2cb68704a5b2e7c890b33b9ba5b97e1d24979" },
                { "ka", "454ff89568f19c0758eef1505ad3dc308b553183d17ecd8e6db331a6186211d45c33fcc30e973eaad7bd1e9d4e1781b4f6d82ff1d3e913152492fc608d54b633" },
                { "kab", "300e0f29f12279450427476798b0ca710308804701af1ba2cd440accfa2df0f50049c86bedc4dbb21cf7153b088412469c469716593771d972373e4dbafae718" },
                { "kk", "3193111df646c7954909fb4d5556a6a27d5d5d0eebf3d9ca4b1c6fd62a7e09c8db4f6f73fa44efa5b189b3d66d99ed1ec35329cdc71d622b10374b535374cf73" },
                { "km", "0d165d93f1433bd34fa307853b204295f0a3fd068b51eef73e90596a3fc2131cfec5fa9aef4bc78b1653c047f9a880f526a4e54f4f4857ae9fa0ad648b810212" },
                { "kn", "3a67dccda5a2546c19e7dbc68dbad9953f4be884e0688bac95403a5c39b64038098a83b3b8a1004183781673886ef674b3a46812f9b76aa6cfec74521ba5a562" },
                { "ko", "c28cbf078d6df1c04acf8f0c29d5cbfc5dd0ffc4143e63e0c1dec4602ad020b951ae088798a941adf24ca34930538a051a235a5360e6946cf35cb0a88373ddfc" },
                { "lij", "ac6fc92cfed0cdf01439add2ea534ba86d60f34be12071c67243d9b517cbb32fe5b4c8fa79986b2bbac6cdbef35d281431a94a154c8dca28d241ba9c4d0da23b" },
                { "lt", "b99ed7c37d79646cbc6c42bc0c2bf1fc68e796639c2d8efa691a1cf57a8a55d74d01fa74f9e2c919294f99810181883cbb1307e29f164dbf18968730779a9147" },
                { "lv", "b120c8ccb63006cc6c20f797aa086d520eb469504b62d2ca83fc6aba71722d231827f6de9bd1cd3e85bb10d7d6bbf49d2aafb0741e568aa9bb678a31d4fbbc20" },
                { "mk", "03d6e63a646332bc27e4ca0e856be7bc1206c771c734f445ef9c1e328a16cdf8641865575d6d36397742a67bd3f75b49b6e2080e403ac39186973143329b46ca" },
                { "mr", "4a315ebaf5836c15d3b19a00e8b081676034950eda7bc324c3dff9971d0cc4fa62bce6fde218f3c3c6ea6d3790bfd8ffd90dacbd91acca9b7c66d396b5f7310d" },
                { "ms", "b706ab366bcd24baec9b7ed0bd64735039bc5dca46258fcba45470c63034d2ead8e19775480308bfdcf7a808517e4351238a657400186c89a838c1e7fd34d68c" },
                { "my", "8b2f3ab04f4333571197e559c34494cbab7b10c367925186f102348812e37fc469e1a83d22826bd9cc1ef1d8dd7b7c7e5be92913cc71ec30a88f28c879db148f" },
                { "nb-NO", "3c624ba759e01b3e259dbb347e4aab9c8fe3cdf6dee9cb5fc3946f12b10034ed2ac16eb4ff917c0ad334d73c14b59ee7dd068a1e9a91f783a55b94785704fe04" },
                { "ne-NP", "a6e606bafc33f7b19e3d4deaad1a09243874d1c6e933042df486fcd0806cd20a80308e898fa15ec92a5acfa4bd30d0e21f8b922a0d1d910e1417975193fef94b" },
                { "nl", "73b8895661f409b0e8eb388a792605e59b1b8545804b281738f06c9c6abd032cb65a51fae700e966d29db6e91d7295305c17da361060ad31cc7c42daafd359eb" },
                { "nn-NO", "abd3f7fcde21b77c241a5e1cd57e1afb7c1b8396dfa64a94598a439736ac4a6800ea149c33f8356f6e7ff99e9bffa3e7425584fb34868f52b1ca3016720dbc44" },
                { "oc", "e95418b17bfc750ceee4d51bf08e84356984cdb0452e719ad11c639a04f60f77cff0ba709fa296ee9f6cf1ac81811e258eb17f3c3a044a4f063aadb1916e775c" },
                { "pa-IN", "2b7e0c7dd05cf788f2c16f4a8a079a27d9914289aa592e3dbbf619f11bf8abdd4bc1856e11db81207fbe837c43c7d4ba2a6c3b7035f24a9d656ef5cc8860fc91" },
                { "pl", "b36d01d4dbe2a228bfd76f1af3438195975a0d4096746aff20d62ca38cd4ebf22a49992f527ec202f6c22670cb1923d5084787a0bd07309f114ba5823a3365b7" },
                { "pt-BR", "a1ea9542f99b22bd4651a2ad31ed0195071dc223b65ca05d2244cb2d538409577b8e1de616625b3ed9583039aa134c0086241f01d3302f275540d7bda89afced" },
                { "pt-PT", "535d2bf6f008e2442272b0b809669d158f94fd45ba0812544ec24f26190fcf44b21b84e4cdac089b5efa22de5e67816662ca67bb2683659d45e80c1843a12811" },
                { "rm", "fa52edfea4453e77da57cb62228390b5a9b907842ba4f156bd623744e5770a247c7b028ed08c176f901502d2b9783af92178f24e8ecc229be060513d9cbaa00c" },
                { "ro", "eabbe78e00f308d3335d46bc4c8a62693de12bbc66a7dce767671a89dc148e97cc1579af52379a33d30c0de7fd17288a53e4999a5f9be1d9608a0162de9b21ab" },
                { "ru", "10c2b13186fb90527ca708f5edf58abd2e4c90df5369ced4bfede896ddabe577277418024081996db8ab1378a5de7703565a3ceec66cdb65a3c6aa2752988b01" },
                { "sat", "fbc091568b6d5661583f7f7b7c8f2f08889c29dbc7ba6f2979681fc9d84cc4d49d09f03c28d9d3b7decd9d909d20302398bfee589dd340aadae0986641ccf54d" },
                { "sc", "2e9b3499e0d81d1511de8776bafff855fc837ddec694ae1c09e5c2e2ae4055fb3eba5ca1805c971a625da4e01705f68c3e154938ff4088c8a7721c967a0b08c4" },
                { "sco", "3709c524bfddf239f6fc447e0b272b7424ad27a7063d6199f7a85c3126a147598d7d1ea16a08f69a7b013873a5341cb773051d76dd9da1087043ba79f32b42ad" },
                { "si", "428ef29f5db4cb8de9489b3cdb192f2f8ef3c5d15118e9f9de4b111fa139c30e9a76cc2f7a4160081d517f784b77cf37226f8ac4933ab1646f92d3fbdaef22e4" },
                { "sk", "29229258dc0d11c83b54b5960b6ed8fea3dd8326daa6931ba7a313b8a345035523281e4f381a7e0b08a49f771f97b7f1ca546900e46bc60fb24baa9e45865171" },
                { "skr", "afb53995c335e06945f896b1fad0f742ffbefb26542aef1a71f6d33647193fdcb18fce21b91481271f65a4b5ee3463bd21a13db62ee077cf8a8676ffdfb8aead" },
                { "sl", "e11fae643f87910f78440c07aed39b09e65c10c19ae078e76dad2d5600fee681c4d18711db2a69b2edfcade1923aa12314f64ac6623d118997253c96edbbeaca" },
                { "son", "e5fbdd93b49b936ac5b379b40f6964937f46ec47565a1bc87be916949262ed49bc6aa339e89932387c570b1f945c422eae3e49845a97eb5354b9f4912059f9c0" },
                { "sq", "eef43024cc71f309567182fdff73ba45c0e11304500a28289513844ae0eecbd9085f79fe84f0f7c1cb3d39e8872406bb45fdf3551a85ae3a43560a6e45ca1f7d" },
                { "sr", "bbd908bfc244b14c735389dbf4daa69b48e9888e2456c78220a9c7cfd340bc5aa7ee519c43c732111c2206543adca315c212d286be438b9da9a8466c36c0c55e" },
                { "sv-SE", "2de120aba6de7e71cf1c1f5826a126f9b54c4bfc11afedaede917b6ef4fca7fbe9c242b2a59fad30e0d5ee8ac8c613151a6e76e375acd71d65915edf33745b3a" },
                { "szl", "2bdc1a9975fa2a189c3444ed54fdff33fb696a416627cfca4f0f64eea1525def64ef7a04bb429814965f84fee2d8cb829bb75bbd4cd05fd15a9dee3181af61c1" },
                { "ta", "5de2b5656e3538580017d9841e4404e99e4958858e925ec19ea981db51b46075b5297ec71bdc78ebdf5ec547f3693f6077a332c07ea37dcf55df97238ae47615" },
                { "te", "0f388f107d1a7dc48d8af21ec24761070af5499881bf36222b43f3ebbcb147b6fd31d7add5f2b52e4e460ce46adfc5409942323f3c0a04a490f63b6ca15d16b3" },
                { "tg", "06367e5cc81cf4200318de9740e1d8c6a9bf0d772482fb7380626ce959a0aca97cf8420995bd52e4bcd34a2580e4b3dba1d736fd1dc0f587ecef8885fd69a571" },
                { "th", "ae67c94c721c4c72ec57243c4a2a66bc889204f41a00bb7d0a3602110e21e416281ddabf1addc3e31ecdc391ace111501927d29a1b9d407f76f096d8681f556d" },
                { "tl", "3382fbcc0e73e2f16e4b8bb8e4cea12bce4b25f71c758894be6fab9789fb6de2078deedb24332ac414292ab510f95cebb5862a0474bbc9b6ef622a559b2a4a85" },
                { "tr", "2cdcefd32ebfcd228bbf182510abf4d76e0064cf21b942b177b38535d433c7cd5f28e0fffaa39008711216f1165e3f0576e8db004005cb1bc9f6e6b953c72e6d" },
                { "trs", "4048eb544d5eb5112b232c3cbd38bbf388974abe87cda6939683fa68f8663754b6f4b87880fdc9cf24f90b8a53de88216b89f914ce24591005920fbadeb0b1cf" },
                { "uk", "926f003e5af83ccefa871cf32ff37dadfe42e48a946c77655d94755c1505851496ca5b3fef400fd878018066a16a7c30b4ad92dd7fdd521c806c37c1cd05895c" },
                { "ur", "f37806dbd1f20b301fcddcdb9c11bf1fcba803b421fc9431fddffd8aef2125bf6616f9bb5d4e782706e60dbe4296769785e9a469d3419fd18ead3dd5aed86387" },
                { "uz", "f5c5481f058a866a9db739d5d2c5cd11e217542da858b98417fe1ac6db15eb721cbcc6a3ee942c007541e800cb567f1c071cac976ed52503d7955789a7a8e546" },
                { "vi", "013853aa658d7f75a32ccc6237fa7364ee6bb5f162a711262cc74cf6869fd10e6aebc3ebe6bb402707089f0810e81251209376b831d56dde12ed76989a1b0f73" },
                { "xh", "24d1e10fae6aaa1b7ab33b02761686daa0f9d4de616fc7e46d1649c57158eec6a1958fd4a5530c4d7a2c5c2e884c4e21f46469a748551b605564d45722432a36" },
                { "zh-CN", "4b2f9e784a582343d565d553923e47d52afa1db40b0c765abbb2751d6fd8d465a393ac1649d4d7a66f3ba777564e87543d30665b1ca49931c936d4b322ae1e30" },
                { "zh-TW", "18702c672defc3e3ad4fb9d6f91b58fe2f59c76f35467b52fe13c9634eb03158e404c0c28c4c2915be7d500de27eb7c58492ceccbadf0036f973b45889e5b1bb" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "3d1b182eb5c92c7510a3c586edca5c485348ae6e25ce4b3e09180e2e793cc050c6334b317c28f277cac01efeeec931a9ad6b75d0cb8256313c478236eba43e2e" },
                { "af", "518fc0b23be93b5a6f8b64db97c6be2950a9387cbf87ec97bffc5fb0d8b2e6701d037905bc8d77df28b008c7e695b2afbe948e9e8f84af300921299b2fb55556" },
                { "an", "11a6c057be86acd8394398fdb26254edd8ecefe079ce67e2994b1bf4ce200678dab17d5aaf248a8a1ee07c7ec55b6230b9e2ba56751767759840481cf8cf8fbd" },
                { "ar", "94d3ed83297ea34652eea3b826b0a9cc781adac46bd0ba5b2b9e25e1c6df1789782a9a536e195ebcb6758fd19d6527c945d5d338b679c55e567b000f8b114e18" },
                { "ast", "6648d4670535f7ae9f46bef2a580968cde72fefc52f811fbb0868eaf1abf4bff13cc4f7d41f1468d4a5bfcb09c499917241abd598b67cd89ac16f65a5197cb4a" },
                { "az", "c58914fedbd689e92eb40cfb2f1df970d97710f9519a1bd8e276b253e09f2eec6cbeece8fb0872a744258f0b5a2abf429fdf0886b721e0a140355d6fdf0b2901" },
                { "be", "26afc0a04a0ae2b2199ac89f197ebf1e5de059c74408c8c640a93d3b9502bd6181dafb23790ff31cf3ed94a57b19c4039db8e58a664dd2aaf82f715b083cca96" },
                { "bg", "8ae2078464f6df6b83dae12c8e1e5977dc2e257fca21988f65fee9f008fd3e5caf8dd6ef6c3e1300f4b18723246e09168a9979df01b40275ff9fc18196263a88" },
                { "bn", "6a6b468c0eca7d70608314356eb3e1815a928ddb41d2da72cad85470d5cc47142b67dd5c16e5f1bcf95a3ccf1f4d69127d66c42e25de05082eb1fe8f7bdf4993" },
                { "br", "d3c3ebd339e69d6982d4cfaedea6aa04716145229e079676c3dd25946efe36bc424c35a4376437eb5325c904215e93e9d23d50939b7c130e6d6413f905b77eb8" },
                { "bs", "e566c065d3aaa8a766c55ce0f982bc89e6fb0ab4ef5251d9f8b2095d0e4b40860e60092f582a77dc86032edcfd7ded27dda9f7165867db58b7c0844432ebd653" },
                { "ca", "1cc6c7016d1bb1d82e94277b3d3512cc4a80c88c0d208029e512ca0fed711fd5b1aaa92633011fb0bfe7a44ba6755778758bd4fc6fe23ac4f73e7c8787fe9ac7" },
                { "cak", "44263e7a0ad5011b9d1479fd5e5aa71416526f58f62733f9c8ebf765fbebe8405e5c2735bee651b25d94f0466473916a063b8ae0470d15f5b66440654c10a45c" },
                { "cs", "1ab37a5715973cbd1906139bebaf8894d7c9422c1db2e4d43c82b693fb9102ec70b087a60f423b1e192bae39082f5993cb0e9bcbc38dfe4397ad78e0e89ef51f" },
                { "cy", "08decefb8a1a89de83ae222bb4236d8677b85da438e7f06d4971f7ceb18ab10b6af1ebe851c1be5999760400f971af764fc486e26e740855a49879fa874709a1" },
                { "da", "ff2187524c23b940e5951016ae65472f1a4f9822ffb158900d085c1e36eccbeffa92e0fc2bc01924af9b104be787b3e49fc7d5dea1a091b9a87a3049d7a6a707" },
                { "de", "10b4adccf7c8ee0d7111a2158e229da3b58533a156cae4dd40bdb0bb0d61ca04e1acd4c5b95910a2669e3d1d8804b6313ec52e4df122405a40c29626f346a7ed" },
                { "dsb", "b6c5d8de9b4b04d8fbc55693a48bbd01087c24ca9ea8e5bc1f111d2c6749ffac6545c46d0c270338d9215fca87a4d6db304018d866aabf5fbd0b5fe9dbbe1026" },
                { "el", "1a541eca0626c3381a6a3b146660aff8bcd2945d5bfa38cd53f6bdbc1775bb8af7a20632a89cc05c12974189f62a248a9ffa6d2385d94e4b701386dd8bc598ef" },
                { "en-CA", "c5effe0635d5791d524b97ca3c10e16ffdc15413923eff4c48c6767087e4894bb8c9d9ee06fa9e91a9b7c11917b8a0980cc7f226fe28799237ed2f6107075e0d" },
                { "en-GB", "dc0973924711d3088fa0731074cdb61aec6269f29138992dbac378a5841a8c772dd667bca6ce8395955503686c1b32f0edfa8a0e4d10a9bbb038077ff9f8f476" },
                { "en-US", "903112be45a1eeee464b5e170f5215e117a8afdb3abe9b349d26eae76e5d61c50cea496c4f5f1eb221539fbb430fd66f6c655ba6e0705fb7575b69556ce9cc51" },
                { "eo", "4c3efa1e17b703a3d019c0f680ebd96f598a5d17127369dba81ec4341162bea4004a3abbaf4c39d44672c4ef335c35817f6ef1d6ac81d58106d1965f2f776c44" },
                { "es-AR", "069ffc47d88c136537f0747aa9adf20d8af00dbfb95c810090be08a094ba32883c4d09b6b09d900a6f0d24ed9142f05f55996110bbafd67388c481dea2da1c59" },
                { "es-CL", "77a18e817cc4c1f1907ff8849fed912538dd928e2164f9806d1b6fb58a9a5fd6c91686ff17669f8360255559c13ae104af32f1cc8bcf5eead3ab04ca22ef199a" },
                { "es-ES", "19cb820d809a33487b79c9bd9d2b4dd7f59e49ec317871be2ef78e6381c0177700e7e9bf21f3d61029af5fe3150d3c9369bef4bcfb7e6dddb266f1554c8c09be" },
                { "es-MX", "ce034acf7db568fd1d4ab74972b0fb107bbabe04e409ef91d6b11016aee324cd03484dd9bf6ad567947abe4aaec4aba1b4733643681fe3200fe288255f7ba322" },
                { "et", "c8430374f9a9f23e44242518967ad493ef55e0729b2bd6bdef1020e33e27dc412b30c93d32346f2d6e1ca134d7f926ef7e82a749559c1bbd995c28f8679c9c1c" },
                { "eu", "fadbb3ff110359c59ada58b7a358341822cc64397c0987bba24c1d47ea8c0f930f80e6a01d52d696b1b0c6a7948b3539f25d9f217da9cb414170b7ce93f50674" },
                { "fa", "e2fc5bf9bd3da3d344e8abf70de31041ed4e96b77b4c0a3d5fdca39a3efbc50271086ddfe9e618f81c8786aa8084a8337d108b97cbc9e2ea4a0734d628faad46" },
                { "ff", "9dc0e95ad19d4d97b3372ffe242c14c6efb6463be8d492f78544456798fb81470cdc316b64fd0258983ec686e8d6393975472903035939e3eda34187f1da1bdd" },
                { "fi", "4ea6ec58b75d27f302e6bc3099b04fc83a667f970feb173f8cad89665796688f29dbf4c4194da339b3022e695e4c8cce157bb0806623dee8565f68ad73d1fbb1" },
                { "fr", "ebd1757e7ee591bb67fd62210a8d8a4aa5245677197c8da01137e1909bd487347ffd9edaeb06027bd4a33f38b30d5ec48f60c287f4cdc71ceb2deaefa6249afd" },
                { "fur", "3a665f70cd094b0c555bd2e312ea289bf32425c63abf3cc84d980026109ab7f554180994722dcd89dbc59f69f0dfac127eb88435e14ab9aba8c6e21faa131b17" },
                { "fy-NL", "b8493c061d6b0bb40cf19346a8cd913875c47006238985a0de81d29f68f95618e305202286a9e7d9d1435a26cfada7a9ad78ee89232130760c2fdc2ac645570f" },
                { "ga-IE", "48a295c904ffc15542568a381a21dda44368841674fdda0dbf68ac6554317cd244718a687e028cfce02480424c2090facf54f4f8e517513b880972b04ed0bc16" },
                { "gd", "ae4d54b604b728dc7eccbaa41711183514870bcc5df3904b95e530c158cee6aba5c73529e49d8a273d615ed41a6b83a29db96d5461bc46ceddc525c54c9eab5b" },
                { "gl", "fa305b8b93455b8819dcc4d48684bf012d54b3d53007987778bbccc74608a4c03655e3acce8ec9c06589a5d76282aee72239df06413e2209d1e3c7fd9f15f795" },
                { "gn", "db879299d2b546597a1a48dbfd6848a30e53b3834a861bdf6d15fe0770e637449622af7ced5104739be53c337d27872fd8d79d92a96f04a4ef2604ccec6afe98" },
                { "gu-IN", "60ff863b7cda5750ba7c08774a7c852575cd396d1ee699d2727834dec4576cf8bc5ff1976f71d797a04859f27b3682de797bf23506b7662ced1bf2c6c5de3d04" },
                { "he", "ee7c457a1bdc601bee5a7c74fa359ca60a9d32fe072202e1834448aa5678b67df138dd7857a640e8bb658b2abd7277526834a0bffdf9731378757050ec0109f1" },
                { "hi-IN", "fde666443ec53437934d302c9563b70fc9f7573c7f509d405d220877c958088dad1da453dd7a7cea94bdb4b25f303ae5ef570f51e3284b4f204d7a8e86b7afa4" },
                { "hr", "bbd1b1f9f6d7ee81a6910f3e21ea8e2a66f54fbdbb7a358875b416e845dcafdc52ad57e0a0871c3eb0847a63c80012e12c32186f575576a1b7a5ec702338fee8" },
                { "hsb", "e565d9574360ac0223b96b13e0cc15f1fe207b508840cc0e4f3bc9679bfaa4f1596b0a73b59d48f20d5aadff9e476c8eee420b5fdae1f2a238d634ddef0f12d1" },
                { "hu", "1d2021edfc90516f123276aa98a189ceb22f7546fe8a4cee69b30c9ca995dba22658a9eb242dc1202af4e5f511a1b610d382f8546d8b619eb5fb6ca1259bf101" },
                { "hy-AM", "69993ff6519eb11b1354815e6dd1f2c26fd3f2647304cbd63167d1c81b9dcdef3487af29856745c947a739cefa8c1d57f459813b3c5aa8ea49bd70a3a13672bc" },
                { "ia", "a8a118adf49f581a4523a8ce2a0a4b504a9c76abfc63a9f88fac4acda82493c26f287485d28e5808a4e6fb8a01dce33bc97f544c8669a0a31db13ebeda21bab2" },
                { "id", "e5bb273269cdc43dfb9988aab49781ba6c7cc9df3c773c6427063a6806df4d9bc8cd98e17d47f86c7be3b1edac4b23f55239e715823adc6a7ea94ffd8b92782a" },
                { "is", "63c456a3ac2a54e7a0133c385099a83c40b240fd2b80e7ae1abf0a7b1da8c52cc85ed198ad3ed0245750aa2c9ffe2742b0c41e129b15bd80b8b37164430b4480" },
                { "it", "e4ea060a52a554e3347ec55684ad5b224b482adeac00a4bf6d948954ee27298ade9e7b4dec4347e50100bb156b0a97f92d03a3e9531cd115c16c8a6b4a131af2" },
                { "ja", "df8402268a2f1e1a98885778b8370648163ea0ef0274246d39cb6992a3df7fc4e1f9c204456e21351186082ec63bbde9c025b88ca020231bf7ba8aa8d740be6e" },
                { "ka", "947be739b981f6f47aa59eaa0ad8762d99cbca374c002b4aeb2a1b559e0f2216132eb69dba9f1048abc8002688277e99618afe8ee6fd5a32cfecaec0c94db5e7" },
                { "kab", "fe450f57fb25614ae02c8f1555151189ea9716d58773782f46e04d0fdea821577d0cf1723bcebb6c3131c797cf9f15b007e6df09cb13b81daf72ebe7a378f163" },
                { "kk", "5af230f1f732ea07ccf056f63a0fa4406c1b84501f99f6b59327a6cfec83535e871bf305ca174e573150fdac4f6e1a8e1faf5e27b55c9eace05a538ed50d0ed2" },
                { "km", "4d1cf4172b6b4cfbfc79a624481ca58c37138abdd3d54dfd47bb948f204a3b7a830de153c8fa1d29049d410b8c2d58d4e5b7058a3d4ad39b2293a4a03531a021" },
                { "kn", "13aca63886643e2d5b99cd91b8f866125c2e5be6f823b1912aa8c5c5ffbf884fc13424a6ebc8576dfe86bb5e517596acb5e1eb4232c3be0ced55673ad781c2b7" },
                { "ko", "47f5ff7d7206204ef89e7cd0ec160268e0793e677678aa276fdd02de571740483d41df7c4dd5e299b517f195ecd93b0940adc5fb8b9d34b7dbc845b9e121847b" },
                { "lij", "db2e4cdf2caec3f73c7b13ffd5475d62d4e2fec6652ef4b056f0bbc6f76163dedb1852f177ab4c4f7a39fd2b2571ce43736829097b94d27348d8979d7480d67b" },
                { "lt", "3300312f54682e52f3f0d8329371d1d31be2dc2ff25447ff3754129715070118149d60f82674c4d5a088ee591a8d67e34858a9607166f85eae2932d7fba9dd52" },
                { "lv", "256dfdd61c09575d591283649530d5b59af7b2bf17ad2defe42dcf09c2eca5af1fbaefcfc38edf8eb4f5b20b8b46ad980d56456d87473947be79abda9588ab79" },
                { "mk", "62af460943d68c94209aa1f853699c212ad5a2261c54a6f0593b87beded06cb2d76bcf2f9553f19da5d55d817bd88edac0835fd6bb472d85e4d36df13b4f101b" },
                { "mr", "591e1a225165232a088db6f5e36b56d7085ac5040ac0283ae7b08240a70f0cfac752ce720255eac3be6c5f39c57ace4b10e081fa43007f64da47209fdc72d33a" },
                { "ms", "56de113b797dfc493760e94abfec9da5efa8fdf9dc93f1765c327a957071f9e9a9e9e9da82174c83ab6ee202f4468ac1e82b837ceb1a06bdcf92069606a26c64" },
                { "my", "1800e5e4f82f9152d4451c612223a872ea7417cf758673257ea9c8cbacffd1662330855845e5ce21e910315ca6cad497cf6b47f2edf62c8e534d7b9f9359753d" },
                { "nb-NO", "f4c1790c508d669f79489ed9fb486e5e7d6e7a4443ce9e5475dd89a905d3dbfbfedcbb3192748aa6e3ee89130c5994bbbab50d992a0caa35ab5429f1a06af16c" },
                { "ne-NP", "c2d465c0699fbfad90b98e20955bebd6ce6b09fa0a8c51b91fd6a3b5922016bef8d782d2aa44781eb597b5072e1216e3f30a5e67c9956d69e300e290107f9d65" },
                { "nl", "54b13dc99f895d440b5921298812ba6894a9445c8b11bbec0ce79e0697dd780afdb670aee4a97c09c0daff40520f16ae626ef814b5554457719b34aae9bbd9c9" },
                { "nn-NO", "b46580377cf95b845dcdbeebe334f66b91ce4add2f59259f6dac2f95ca4e8ef4f8c737abe9abf09e95daccf4962863061b3b1526b6e46d66965cb74a4c7c88e5" },
                { "oc", "cd4a66148bf7e46fa30bc735f6b94d31c039d8454e002ec4d575ad1f9379eac5f244c1d0d1ecc528a108058ddad63298e387dfa9a30051c9192dc90dce1c6b92" },
                { "pa-IN", "960f67268f90094dc7f9fd94714b6ced48e7a324422661d5ceb8ce9b5acbdaf8ff1471af3b1f3a020b6c3149efa503f151a02af225e6bc21efa9696c20f988c3" },
                { "pl", "83daac5a744a404031d3be9ed5a0aeb0282822fdd22646b47c60f8587e798da982d868d90afd063e705fdb94933561a2db7fe8dc439dac6b91fcb6b15d197238" },
                { "pt-BR", "7e9d614067f16dcbd0fc2f20e0173b852d691010d5b6ba7aadaa46251dadec76ea95c0eb76232a412b70be512eb4457fd8bc3cc9368df8a614e0fd5a95f440d4" },
                { "pt-PT", "961ebc7fe42b9d606360bd2c4a99dfa83b08ca0c2da33083d96ee3e43a0d11d525e7216b64e40268a595f0e81224968e3c71f73f130c042e334225a7771912f4" },
                { "rm", "de7e0b2c6a40bbc7b2355594333d0fab38a7130ea1aeb79669dbbd377d001e7c0177fa4bae63c4673593ce21b7ef09b8ec897e65b557a43a0469771e14ec8f1b" },
                { "ro", "93ce8f4e64278711596ee6054692ed6479e1293c39c974aaadefb0a2d1241bf0e5566b41d21172f22d0131fe7377eb4a13c6eb33f0e78cf82570550520707d73" },
                { "ru", "c26a3658363264687dd90a445204cb83612f08e8d5c8616e3209cd3d99b00efc2d792ef2431d0b28025e3ea3f8e3bed4bd8f067160b0a79c17258f89c2c5517e" },
                { "sat", "f47bba9e97cc73ddf22c277bd3055fa96995087be157efa0d1e9e1c4b5eb2855bab9838e8aaab030ed8965d969ab02cf81fc1a32478f20b03c5657f68330d195" },
                { "sc", "2672cfc2f7f11b7d94ae7fe2763a33c6a6e509d2dc2a1e7368dc8a9f0f501a7087ea4c179b83945c89dd733842998c988865ca784a91a59040ae1a6a08c0a330" },
                { "sco", "d6276e7d11f4aab57de7f8d55422ae9fb422bce45fc6ff23b43177cf7c8b90f425f2ba6b2cbc1c744ccd3304462bcb4fa37954a10eae256c01cc27b5435d5df7" },
                { "si", "04c115535a970261ac1df6caf2231c3e65b0263a220d80b199c512acc4cc7e688ccf7a8c8cd45c15ca349ea2e0550a919bd64648fe52093058c56d6b5c0fbeec" },
                { "sk", "ac57046e152ed5fe0206f603d676fa807c2e4cd85d850cef84e6ed6d59a15434ad51ea65c3354ce0ad1673bcea712dc15455198a5e68bd0720e8f58f54c9aeaa" },
                { "skr", "c0e2e51e914568a3105d89f18bbb83338494d6f8d2943ba7c0b3fc69baf9ea2403bbf30d300195e9b611664fe14eb09ed11a22fdcf5828a85d1dd9c7650d1aa4" },
                { "sl", "f10b9dbf3f2c57c702ec5015abc5770a8bd1abd4a749820dddff888743fdc3b351c0ce0c130fc7f479d0a1dca089cc47a05b0aa97ace4fcb49897f22847d73a7" },
                { "son", "291c94c0652b4c7b741b32ef33f247e47bb4f4a369bdd5d8b1f0879f7695a745fdfb4cc052d303e6c05739af9d376c16616a57194dc645f23e2782148de2c4ef" },
                { "sq", "de264e4a41bfe99556e011f72f3007625aa47ecbbb7301e8e96a4f5b3ea76e8b5d85a2e07bf9992c46073bb3459ba2b4b0f9e13b5eed98ef73200025fba61320" },
                { "sr", "44d0bc93a441ab057c76a3764feaadc7c87b1f1ff6bdf48dc8a9fd0648dad54fe55997258aaee3d0522bdea493e1c20f36b98956c8d38bcaccc7d7262b6af264" },
                { "sv-SE", "a14faa2f7539d01d952cfe43ff9ccfdbfab2474685fd794818afe91945d7e3ef2b822c21370306777d5d49eefc8d851bd0f138ed93c0f5c78287a162e9c27b00" },
                { "szl", "56ece27e531bb7b02740fdbcbc7ea956a93ee26d3aceb388e73329a1044122bfb019311142eb11b465f6ee65fde4bea9e402dd18f10853d404e4d8afbe6d89c1" },
                { "ta", "c1e6b0de5b5cf8c02efa6c0f2b3e48ac5e63a5f66cb15dfa80d789c34694b7ea0473576b8905eedd5078892646f1aec1aee6606be2f115aba0c6022fb846eaa9" },
                { "te", "74579d2f99ab88de4b8084dfa0266f1170ea77947c72b5ac55e72a887a477ef0418e2a4fe5cb07f867e75ecc6160d1a55c964dca60aac0ab7d58bb502e64cb59" },
                { "tg", "c715359640a1a6251b7ceb180f1bd9b5dae301dca7bcca69f4a226f85b9df19341ce58eb7567e4448e75a65a544042d51fd692382711f4cc24fc2359fdeb9a39" },
                { "th", "3b5ec3e5cb3b66f68e54b71017f27c3eb307f4645a99693cff858b2828d797cbb1555392109135f027d7962c749be157dc2cabb07162708a0556f6f54982d2e5" },
                { "tl", "2b66e63be531902f7d68e159e7879a87714cfa0905d444848b06e93acaabe532a2e2559597221fbef14ccacc2d2f800497864467146d25b36c47a7c4b40edb55" },
                { "tr", "805b63d546df6976c9e0659bd274395e24065213af2a847e133a4b6e31b8d3e17d3fc630f62dedd157b5540acfa9a562452cc423c774e1ef0aa489a1dd814364" },
                { "trs", "0cccabb197c3f0e1421507d664c38ecf5f0484381ae345b0424d09dd24bc3e5bce73492029865d6c38fb45bab4c641221d6788b245af531fa5aa4884007e94cd" },
                { "uk", "0bd7dcc2bf7b56472a147d31e4e981af5399171ae41380f102616e3bf69eef1b162a9f7f6f05a3dab1e224d7519f2ff35924ea88368e13201a02375a64530590" },
                { "ur", "597a304c1f07f73a01bf7b134e43901d68d983c8031b866802893051474049eb80e82c2d98115360bf8d96325a3ff1c03c360f1ebf71e639b15e303ba56adbee" },
                { "uz", "0eaab529874df7680abd206a7c87c807f09f2529cfde9a02774ee6983c47c894353742bc47ab31910e19272b0d46994b7115ad705825674d1d13a1c510b8dc5c" },
                { "vi", "64189c3f28157a3a4b8975d0e35e8820088e4023e67036e70a930963941e223365e9c9f42bba8ac596e41f705cbd6055bacd2f2fe865e301bbe9b27667d33a22" },
                { "xh", "b690827c867c31a9822a9e4ad426dae7e6d7aec1a2ae4955aaf07ac2e8dac7208a94137362f456f52edadd7ce94a9697459f3ed16ef1e58dab86b19aec995c8c" },
                { "zh-CN", "d807b3ef9db1f6fa43fa658ecbd141ae1d0c48f5246491da2a122d94bd2e7842a819c82bd892a2afc9a7a38834a0611562d9dad2b2313bc7dde6f9669407ee22" },
                { "zh-TW", "fe1d033106e1f15e2fc8e92d8155e5a0ce675dbe60ccbd60e2d80d604ae69df8bcfad5ba2af63ef6765ec33ad8c1b9e269ffa88f45d8b64ec8e5509da3e6139b" }
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
                // 32-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
                return versions[^1].full();
            }
            else
                return null;
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
                    // look for lines with language code and version for 32-bit
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
                    // look for line with the correct language code and version for 64-bit
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32-bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64-bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
