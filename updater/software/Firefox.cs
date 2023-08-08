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
            // https://ftp.mozilla.org/pub/firefox/releases/116.0.2/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "571ba61b6c5de841b3715cb797a18524ea1d515de3f08691de11009113977f59cf4a9025ee8275bd8200efafc8a70ec9b55f1c8785f4d29d5ed05879eae2977b" },
                { "af", "b7b316ebde49dbf0a181c5ce7a38c3ddf22735475d5fac3f3d392d021671519e88a35141191bbc353c5819238011dedb0c789100c379e86bbc8702f219728bc4" },
                { "an", "17bde529f9e4e9f1f44170d147715050157aac76d312bf17ad9db9a129ee7faf58300fbf59ee1d962be67c7bdc1270e720b2cd255e82d1248bf05a205707df7a" },
                { "ar", "4c8c8252f778eef6500ab12c0b5d32b637945fe5d54db82bc2ffafcdbf5cbd0a3d9f374f1e1e133e4c1c70677536971c967cde4aab65ef3993033d100dd18cf0" },
                { "ast", "04fa04df6569bf23ac87e073597466a40ff9644eea75c86ef88c3a8c20ee4de94bc8e5ab3d0a3e045cf38c11e8abba7f102dd4c166641f2d9a04162ce60abe57" },
                { "az", "87d52af16e8a04597f2689167389458dd354522085a4a9b119a6afbe1866a8615342a3a85c830653e7ea5c59ab249bfa8b56a157ddb51a7044b26b16e1c893e9" },
                { "be", "52855479aa439a0dc3a899ecdc04f2938c716d8b86b51708c03f50a19b17b72df227e875fdcc6f475e56780c426cc0ac5786150b4c3d43ef4e71ee85d4a22ddd" },
                { "bg", "9bc809767c59bc039502c85e283fb8bf7568e3d50b2c9f068e1690f80a0f8711ff9d7078754ed99d53d77f5f8623dcc8c92fe56cd5e74374c0717c96336c390c" },
                { "bn", "9fdc70bd283e2d217b83875ef57b30105e2b2204cf2accc1f8af77dddf55d8d6c253bc98ccdb339c22c03568206dadd51d921b3e918a2f9b2471dd00026e3d2a" },
                { "br", "b1e28a605f523aa4c954f7e6ee0315e9230c86a323aa7b80ff9b327bb6f37a07c132c1551c078652658e343895b3c6524668a146ee6a5c75142eb70fd7a808a1" },
                { "bs", "96b6cc8f34499ec909c8a34c045ec4318141b643f381e2a7c4963364efadd18162862fe07cedbf02ffbc6c5058422ad0ade5bbc96ac67d7d5aa0fe71592557c5" },
                { "ca", "607deb2a1f4312a58b51e37bb3d797089c200e113ea23c0302dc6766535ffc163da4c2bd88cdf8b4050f750b28991dcfe770b5d62b9818b468265e14185e1146" },
                { "cak", "4f54bcece0a9601d85f8f0eccf2725bb23e654efa0a7869f96a2c45e9f309afe47385a3f16c8b4dac40e93284c9106a65afb4eea570bb07d66cd5465ecc7f60f" },
                { "cs", "e24e53193fd2cc798e3d8ea96ac7acf55cdb71631567ffe3b5db5de31b66ffb61ea045bc82ed90b611f655d87ed4efaa1e1b3bcb8ec0b40cbbb228081d7aea44" },
                { "cy", "719b59bdcad0802db77254a49ba2e8365cfc88fd23a8be563d75dc108b810358a3247bd5cd93dd5945254402490764edfca56bb3a2eb2c14c667ed377a111979" },
                { "da", "05944d65b6956d7ef299bf2c58f6c13041e51a5591e866ed9efc286f38c3ed9e74996c74b9fbdbf3c2bbb430ee82e9ef214e8577f602658c4d48dbf31872c55f" },
                { "de", "064b234beeda41df722eaaf9d5d850800f586f04af6ef97f8767b0a453bdb4aa2c537e05fbf3cf6bf365b45e92b53f7d271651c0a977ec98cf8d4d7c2e6794e8" },
                { "dsb", "8e8b1464c7e9370be3cacc376987fd0913347284455dd20f94259af4155c2848f859c045461251e1a658da643801b0b1a3b3e8266f3eb3255d71a84ad3dfa965" },
                { "el", "e04e8b8014fcfb4308493d879794bc8a51a62771055696bf7bb65037481cf32efd6b8f2efc0e4314c7c2af44b8954819c3a7c8c3d919708f5c817761fca5feae" },
                { "en-CA", "acf9cf54da8b4e4d5d6e9a885459ef426049bb3d2b0455470a0b1afc541d94a35d56ce55a0a0f8c1b3d7f73ae451d025d188cb3ac3022cb0d0c9d0ea897ad95e" },
                { "en-GB", "f08a0acf703e3b277dff9c6b7060665c3e153ee72b00d4dee79674a6d5a41ce43149cd636cc490a5509e57a6a39b755a133584166edd18aa6f081d3b4f498d82" },
                { "en-US", "599aedf2db3bf87f06699dad133161beda7b1abd2e7c782ffb520d27f2fb2d510abfd330426cf26e12f9369d6e9a28e709ef95f86008875fb8e7872ffe2bbecf" },
                { "eo", "65df021eba685af8020f42386daadb3cd8437cea968c8d9315a6b4283f3380b246676a7e1868cb3559e741829b16d2171f6f9b8f89a47a352c8520b713cf0ee2" },
                { "es-AR", "6a98efead49d14d13d095b0c9b0eadf694001c4b1f322723be1065c1b005190d2d0ebde781c23838b1b934a228a6e14150895bbd70970ba7cc02328704669ca8" },
                { "es-CL", "a631bf15bf62b6c3817cf4ece2bbfc246051441a8ddc7de316325a85954d8805f184bd2af078eeb92f82e026e4a8ee94016293ac915faf305991dfc6c1648188" },
                { "es-ES", "75d7a43be8737d2253a8a6f449684ad9849a11831629c490dd2f41eb24fb37e17850c4b65b3f2f1fc669833be37a45896da7b3b3cb359ecd27335e118fa9b528" },
                { "es-MX", "01f9fd7b94e7084c55e398a52c9bb0302a877a0d82980b840124b4a890f772ead234febdc3786f61a10381bc246f252a8b01ae8eb7e2ea84963bd6404ae7194b" },
                { "et", "4b046a78c670a26bd26b5b2ef4409fc7dc7819a4c0eecd6b7b98dcf53a34268b7f1c9722a18d97cd011087f4f3b1e5ab66ed37675b9b8e531f9c82b9f031103d" },
                { "eu", "50ef151c627601c500fa6e5a4438489ec1ff8e3d913ed4f5786c57d7940e833d2dac0ea87f5152a03596b78b423040592f1d1b390a32b1347b474733f03af7d0" },
                { "fa", "380bbb43fdafb5367198d8a9c14618442b3253148b8bbfd3d5095f8676851474711fb0d77230f9492a359bd8abd35b75a23e43879cddc0fc85375b9f6dd7773e" },
                { "ff", "c43de502fd8c4b70bb9e8efebf2eb8813e8da30b7f76b9a6f112476e669536c3e065ee729d8d63a8cf51ae95bd607175515319f062f8c777d7234c5c4fa13e3a" },
                { "fi", "33639f9433a0932f0ec7626f305a92e276088e9a8b2dcd3cd4ccd042ece7a13785b9ca63175b902f9280d267e45f9a636e78c17a50aa86810f798a77e6312c77" },
                { "fr", "d426a1760a7ab22bc456a37276436e91d8492f6932fc8bb40882099e69e8b6c0d5a79b86bc7c075bf40a5564fde27208baa34ded84d08332fd467b7abc5c122c" },
                { "fur", "7348e9e8cc6bb0e1fc5b7cbe0037ac235c76612ee52888128df4195b8380dce2dbee434a94fb2c55fb42ae8053aca49bc5995f42a867fcc9687b7b8fac98238b" },
                { "fy-NL", "d1fa2ce6068d055cb8b65a0195886bd0a28973bbef55807a5824af2a88ef9bc802c7b9c2975620800904e73231c5d316b25b89378476124af2ff28c6a481bd54" },
                { "ga-IE", "ec9d4a42e66978b718b56a71865add88d5d5f0b2dcda1a3143f3013d5792885733f6039ed0c178d021adcf202fb54893a7a09085bf3407d1f818a3e8f450770f" },
                { "gd", "52fb9b7538cb391c7a32273e6271db1a32976608f570592162c8a5933a6bf91f0cfd6c35e450d51cd39172330b677d15dab973b25ae3132d4054ddad37996b53" },
                { "gl", "6ac30af4100dd911b6d398080792d51f9f66312548d4a936b60f537005e9d0c9124586a62e857c605bfd8b10fc4c2f3f93d563921627e590102fb0b4c36e901c" },
                { "gn", "6e011f0de1191047d1772ceb8c944867854b07a5fe58111f3d32a03a97eed235b79f6c6667b9ac4f4142986f735ad06a17ad990cc5669326ce8cae403dcc9c5a" },
                { "gu-IN", "f54699d6c9c7eb231389b7086f129dc54fb9833c5e4cb6af782d13f972e8b3d5fe45e57c4a107c8ee40c5f73496048829bcd6dd4ed2eeaaf7b3fdd3f66502a46" },
                { "he", "360c737d4722695a0fe9adc55ccb3c2448f041c1bbf559eddb83fe6b31c038c0ab6519443cd5a8d158bb8b436172cf75b92b3ff96de270dd662a508b14d93b56" },
                { "hi-IN", "e0d21caadc9302148b69be04d65aa9bbd70ead9ff28ee3edfbe630154fdf5c5ee8a8b63d022fe44f99092f19a021bb1950616b759802eac3e18d09c9fab0abd9" },
                { "hr", "ade1bbd0c2d9c0554745d08ed3568320e9457a0b2aee4247833a9f52858f7af93eab8bfcb3fd71bca7dcb2451d4600458c74f347f13c3e29bb77383ee0a0f542" },
                { "hsb", "5f5ab0906efe5e76f5f7265fd766a1f8bac4b65b7f21b08f9ddd6ead6257b61712744ad3f6194c3cc8c2d89599e35e822bdd4ed2157fe0b76e64fc36988bb830" },
                { "hu", "98b6a7918f307f8c999ab6c78594e8be896deb0f60f13df5764040cf9d24ff5d294c23e166994c3eb441d05ff558eb3488558ce7b336e1a4a5589bf645d930e0" },
                { "hy-AM", "cf72bdb42c5886a67837b79a440b24ffbbda166e70bd1a760a8d60587b066b6deac8e395abf0cee91aacaadcfeca60e153befecff9da835b6e1922d48c0e3709" },
                { "ia", "8bb971490922aa61e6d4219cf9657f3e75c1eb204a6c154115af3a89371a7c3f1bae8c00ad718dcb1215907a09551302aa32c14da397cfd0ac7792a18b4b83db" },
                { "id", "c9bf414262c2b9508bce7f1caab06f72af43b4cda9a9d6e0d13b9244689cfe801dea6c13e9c79b5b7e5ce2202452824e7d955bfb6c8f6b4c296606b7a477fc06" },
                { "is", "06d60b3f87845c7172633f4a8dbf9de8db846db45380b83c5e5606678daac20dbe3dc6944c046092efda20008f79ab999db9d45d98377fc46f4b2976a78262e8" },
                { "it", "9bd0c755a484489445a734fbb02aa4157127a6e27937b93a2fe4213ed1ca0fb63af367b631111ba228705d447370a42a78fa5468c590266325e5eccb691a5c2b" },
                { "ja", "79586a0d97d77ca4ba918c3076563773e44837571efa2bbabba95f3b4644fe027b6cad0af346c50f36c4e31d16dbd5187e9ad1b0b13d7da4d0acf50e7d775414" },
                { "ka", "16c29d9df545e9281a31d132ed94fe44f56f672661dba9967c500eec67484beb01f2cc81c655a7b484603e6bb862b7e58eb372fe45ff11d06b61f6fed65bf504" },
                { "kab", "d07bf82b3c5b4521cdd5f25fe51020e2708a450eb956682c3d1930bc565a0460f8e9ec60cf15a4a65d19ad53b90596dfd5375327d9c56437afed5c620ff63a89" },
                { "kk", "4b3217988d4c8e6288e4f714702393b3750e7cfa5c6138607ae676de4754a290d2ee8b3d7dc828796c6258160b5be1e070e62ed9d141e5c1e7cd15e0f4930b70" },
                { "km", "dd05611e4345b49d74e5590cc0e289370a5b4a1607951acfb553a92c984ae6079e0fec998f52a377669ef633267669fc1c5776e2b58e24763976af277c742f01" },
                { "kn", "f49766806a99b207c6d9212f0c3116530a0288ba6782ec902fe35df0ff771394484149bd9ff2722d4d95547a35139a1eff27904cbf53b5f079b4abb132243b5c" },
                { "ko", "8dc017941c57cf2625aaed9e0f1c3b28ada9155bdbf2090e4a6460b5595c96e5e5cc8e52a5d055308ef578931be9d8e38d06ccacf39edfaae568e6e2a5c8926c" },
                { "lij", "e4fd12c5ea557fd2dd0879ef7a901e9a243875ad0d9f828e1c3e9ba20c61fe87ba7ef7db6ee0353c5121dd8cd33f6f97e563e23c48d989eee228db8b4b1eccb6" },
                { "lt", "ab6f6bdfcf8431f3089d529c036581b4ba7250d38c5431d206ac973a21f714e9fe9ef7fa5891a9bd26280f952f16f49c35d32308061472d17b27a05d51360334" },
                { "lv", "d4a0d0e8ca46b6e5c32aa71e216a66fc1b982feec5928cd219fb567c3c1884d9ae0b78277add5f9d7102562f9937cfe61589e19fea36aa53855bbae3b2cd5588" },
                { "mk", "ecc271a54dc13df12aee560d9158e802ffdc2e71ec82ab3d9038fea6b5aab3539cb4db89ac416eee7359d89293c114347b96b8c56fe36e224147b90fed69ce25" },
                { "mr", "7c9667f0f727ee70ab04c5d0025f0155c6bb7246417b04a9d2125fe2f1ca4b53f63143a7c8d06b95dbc3c316460d3fb1e569fb0441a8c1e835e81f4e70176ed5" },
                { "ms", "b433ee30472d9dfce1882548c95d723bb789712b56ee68803ee1ea35ab9e1e4df61ac5e691b6978c32a0cff53839938342b0b3cfe73f22bd8576cc59b77a6da6" },
                { "my", "d323cc34dc96c10b0da32d76b02db4516b3d6eca59e3c85a785507d470c9334d9a0a5e10d9dc6d606520d5abfa8d43d28374de10525f5c014196ffeee3fa9b22" },
                { "nb-NO", "2f4e53fa934bc2a609941a0597561938d3d29a2ae832f2ca98fcc803eef206661cbfeb93ac4dc23fbc4b677678518a5b87b6d9129fbb526ca817a38a2b4a893a" },
                { "ne-NP", "d73bec863197b67e9bcc951c9943babf2b5b476d198284f67f8d8939ef18ac253679b2c91e0f4f071b81d75df404fac8b9ed950f0e1a732e0f0e1adc123e80b7" },
                { "nl", "9f7c2f7647546a4d005fcba3020ac147adbbefd9b0f9140097c732779bba55d831e802b6ab72ee88f5f503f75195f320a63d44db06e927b1c10872c860551844" },
                { "nn-NO", "c4d744d964b1c5eec744aca949c1feecf5f887e357b13b25ec77051ab4b8e0d24437da8ba75c934d7904a984fcb5edd2f41f16a68f7f2e5aab1ef96ce7bba5d9" },
                { "oc", "540819fd759967d20ed97352ed9c462da0e99b53fb4788d5c34d6c3fa014bc0c72e972cfb12523ab84f116ff7cf969e3e2c07808515ace8fda42406b9f2f23fe" },
                { "pa-IN", "9ebdb95bc81c38c1b3eb8ae9ea89aa62858b6bd6b1faeaeb944610973a0e6309fa23f3fed4ea148c131d41ecfb89a3fdf956578e92116dd9dea0c5b39ae2aeb3" },
                { "pl", "9e7577596aa00a47114a8050b8b68a19e87aa04a7a668c59520416a519ba59deca8134b9481b0c737b7fb0a60a5f6bb58792f18fcbded7511473d702de944c91" },
                { "pt-BR", "9740ee7e8fe11d598aea4a8343c922d364c524c01d1ec56998c36a973731c6695815905f5a63058df6b4b94bb6f6f0b278ae5799bc99c1f46b73e2b8f90276ed" },
                { "pt-PT", "fdc0cdedaed911ae76530da003da9208ee4d7e7948845eb8c592569251367a574655d662a640d903739246cc109e0cf30464c8cf7b2e766f0e21d9fbeacc3dbe" },
                { "rm", "03f7d8f0096f00b5148aeaf777dc404cecd56f770008c4dc7dbf103a551105416ee7880a330fa0da9490fc3ec8b3306e0264db2e891d2b0594f269d7baabc7a3" },
                { "ro", "4e08a25b5bdbe855cb2487e47a3024f157af177f61dfb339da2661dfd3ebed255ae88d81ae07be1e0d0925c48da92fa841da0b6142df2042a5a283ee2fcfb34e" },
                { "ru", "e4a4d175ceb72d7836beb99516c50cd94088636858f7179078c8ec3a2a5026fbe583d8234f8914763ff2087eda6f2ad947e5c7aedcc4f94b39dac23bed2adc61" },
                { "sc", "c603e7d140f7cbdb6d2e36e6612eb771d97cab83af762f45bd77fb036a3aafb809c6aabd88de685f44bd5c3323d1a51dab7d32bc6ed56f4f9a53e5b82f71a7db" },
                { "sco", "65fd0ae65f132c53e991c857cb8ab0a65905ec8bf6392179fc0003e0807cd303598c90f0c575f2012e7518fef768194a2c3cee0a5b5025878a624006df98a7e0" },
                { "si", "39eb1f14ab1abcfa8b512d10927c93294cf194f2d610f5641fac9d6c24b2073db6c53ab50c5e7924e2a6c3fb0e0eb57b06e7ccfb99fa004ed6a2f748ffc95418" },
                { "sk", "2e9d5b78718d8a6048290cccb0112c2f3f237ea4b76103750d9dbef475b04805f743d843ada213bbed5fadf15d8c7a3f9ab79a0d712552e39d78775fb1a29ace" },
                { "sl", "8ec2f9c4f63246529acc31867d3bc246843f4413b94e7d6aef2d202a9ba42d5984bac554b17bfa066260ccb4ea09e2a745099f33454d9407ba740231882706e5" },
                { "son", "96ca46657d89794f1ed1ac48fded152898d0748c5362804950403fb35e51524d295e7444ef8bcb8a2de1504e20ede091b1816639889f7c6c021fa4879d5561da" },
                { "sq", "54a9187d36883d202d8aac52afc92bb3794307f7c3f57bb876e59577ae7cfc641443c28a7d35677cd0ba404ef8849a9e2f50fcc8cd270c0baf1274df83ad8301" },
                { "sr", "18098d472ca1c402189a66f9e91d3c5c6ce2badbd289557fc0d6f1df044b77d33319215610d0c42c6d43ce5d0b024b2afb50ee6929c7c6821f001781ed23baf5" },
                { "sv-SE", "56acabbabf36b84afa9c7b34a930871107bcb42fa98932d00be9d7ce523c85962e921024b74e54b91487fedbdbc8142c454d511009a04392b149405cddf15460" },
                { "szl", "c6769e6112031c53a0d575c76ee4bf10362746809f4d6afb5f7ca33e2f36cc98524ba85794b55da93131823166a9ec200453ff6d7bc4efd428267d5e82749989" },
                { "ta", "438a594ab742239ff3497544f61ea2b3b79dd279229a5215b50c4cf10dc98960433a02cc1c948922dac3c96dd16c6d9eb61b3abad4ff5e0e892a9c537f44f4c6" },
                { "te", "f7c639f23e6b28fc27ac14544b22cbae7db1705f382bb6ca602d8ac679723ef89562a7b27fc82f4bd059281fd548972e207e64895a1d58bd5f857ec0d136424a" },
                { "tg", "02e1bdcbf356ea6e129b7e56f87aa0906e7b043ff66cb8bc6e17ae3475472952b094d7c1702d6072db39e1965376efb27d454f878898554bb0dc7b9252dce38e" },
                { "th", "35580770ea981e84165104c475fefc97445fd477ce833515c7b1584e5a4ea58485a3f6ec1647ac400e66f5a64b4cb26785c32678eeef874b582ddf7f256ee0aa" },
                { "tl", "5142e18350aacc468a03d536fbec1cc0213292cdfae820a4860d5b97f7b78dbd06d29f5004c27655a0bd0ac9e22f620786af8bbbfbf949e7bfcb7a1566050d7d" },
                { "tr", "fb25694ea5ccbacc2a1fa5685a12a8733330aaba586db89170bafbe00dc1f4f12d3598e6e62c2c33557ac4a67fe0d99781096a2e920adc64d61e26485e0f0e91" },
                { "trs", "2a8975479a9fa7870aa3e4cc6e0ca56de22fc33042c6037628f2f0ab98f055d0aee744b2df2d8c1e1d917fd09449ce8e029216c01a97ef919134294f3554b11b" },
                { "uk", "ea5e1403c766c22bf5fe32968c970f7701d6cfc85a54ea8779a524ce966fd805de3bc46467aa5ff0e54d8f917835b7d2f6008c7285091d751d556e5f907d0943" },
                { "ur", "64cdb713e8057d09984b058edcb3e0a18a5b62f273d5f89180927d6ab56b73b23d0db72524e12cd4ed434985cc1e16974a82922f7b74aa93c74ac3a11007f3ba" },
                { "uz", "9e3f759c943bb6bc68831106c031749d5feb18c12a17da582481c605628815d5a3181aff1977c1aa3b626b33f16ebefe1462c5c37f2f48d44d13be25cc8de1cb" },
                { "vi", "38e1f22fae4d4a586b50ae3249cb298a33dd1dd745702780fe159c68ea1e7b4983511df3dd3d4596e4914e3f25c84e0291ab586c21266452f4c78c1f78b928d0" },
                { "xh", "c18d2d723965041a97e2cc042597a06a08af4aa7f5749760cc2da502917898f592ef2d8ecc78e0455a95cc25e3470b76489231129c3d1313ec5e9369609cf449" },
                { "zh-CN", "35513e3799043cf06f1ff0b79a34d0a8affb98f9baaa84eff7317839a7f08b795dfa46e19e64cc477401263d49fc1facf3db3cfb7f2aafaa6a0a3ec6f5b0adcf" },
                { "zh-TW", "4e1662a427e5846032589783f1b1172ff5cae6fb6c08dd64e2d13275ca2ba477f36e3b3007827f6d65c309cc809690d8c1c61b7e0c3433d1fc646ee6f65c8ec5" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/116.0.2/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "184db7ffc2f82c4ef5d9b0bcaa458772a2391e395fcfb639292e11d2f94bbd36cf97adc224a9ec1372b1799d99dc55f50d691e805f4b0b72a223b293593a3fc2" },
                { "af", "80ea65f400a87872a4e817e18619bfc27b4180d530d0b40a32713a2d85b9a5b5013cbef667e78f919e9b72d8fa26a3ba49ba1fb2f37db376dd219b404b46b191" },
                { "an", "7c0b23ec6d09cb2dd6d840c002fa41027b268e48c20629fd1349b0895cdf7784011312f4e57e28528a5c989301eb5308d172f7d0f22a894c25deff0ff3ca3fdc" },
                { "ar", "94053e57129f5b4ec69d079608909a7873734a3145a117f858db1faa33a9903d7fbcb003308fae12fce99eef5395e2ad595f948c468cacbd0a0bded957358c65" },
                { "ast", "4d946e848681a305d517eb22410ea1248a6d5ab4b770797df80d4d8af5f46917e46fe4d2301921fa3ac8d497eaca5ea93c19b68bfce64bbc487c747d4d901e11" },
                { "az", "679a456c9069e861f8948040394875b2487f51c72d56fe011328e9515468d39b1b031134600a87c5c5e15542086ed19258d180fb52ffb3b81d1f84a591d242d1" },
                { "be", "6e65d84c0244692dd74f5cd104a1e57b8fffed8f6cb0af9c782bd19ee55bd02172a586d7872758166b35d32ba30af7c0cc54144078b6e8a27f28033e02033f0a" },
                { "bg", "e53d5c92aa193b0a9cb77a68104b3587ab0bcc474b043fe55b36fad211fe865ec375a2e3a7d1130dff4ae6ae8bb2debf5657b0b75e906f4ff119e1af9bedd4bf" },
                { "bn", "ec1948018c5a1f9f80b6e73b1b2f8d5df8be434b3f604e1ffde57ce2b3c5e61907854d4d39de06175151bb3f49641b2106a25d5294d28cec1192f444dca51dda" },
                { "br", "d682c537375d77314bdbe4271c02fefe32985cfb6148678b727f36eed9e655bf431658c74faae11e680398366efb9c40da1d1983bb3cc796aa06108793441eb3" },
                { "bs", "385273e18db737f620df78e95b7d9cce7b6dcf1faf8bb8a72cc185943448ee67c460073b9de2d716189d61f435a6d35110d29696cd0ae5f00d9f7c623571e7be" },
                { "ca", "d3e55e9aff9d43f20adfb402b77971c1050beec3bbcae3a1178d7b32136a1be61a19a47148262493771dc6e1d185c1bd92d9409b9f49dae4421f859fbda07d76" },
                { "cak", "7fd4c82b5ab3ff38bcd30640bf44e04a9dbe9c47400fe1a5db2feff32c821de6fbc2eb298bf53963c03ae5dd070677c254e59d0a769837cfaba0d9dec1e8acdc" },
                { "cs", "eb5812ac8a33d9d375b74865bc9c0c6e4f4e7875dd8cc82ef546dede9da9f91e8d0e2329fb07eb1c6810e181c3c58d9e6b6ef4be8b914c0b1d1087a1ac785abd" },
                { "cy", "2dd3e36f773007b5223d8afea8c0bfb9f252bbdb2eb2c916d50541cf928931d29bcaecd48cd10d9f37818397be3c9d7dfbf62eb080c3743ecf0b0139d4b94212" },
                { "da", "9d1efe0cd44fec0e10e2df02557beecbb788a3a1442724533fe5f3d807fc613632a8b9d347ef5d0969609c6787dff8d299870136bed96f5a033b1642213f2ee4" },
                { "de", "627d9cd7fe772707b8b8b0d443ee564e3d455cee81ae4551f5af4cade4b371f147d6ad7238f7c5bda86d6b143f9200ac6ab6821c7e22049f4be4c6feaa0f8dce" },
                { "dsb", "825387eea9d09e6f03a2d6231a15519b142a0d07763a93ecc8381a6d652f9ec8c9c591d89eb01282175c01aa2ab8373de7c6842a3b4fed9c838b9e2ce6dbd0c8" },
                { "el", "dfb030af7ed6c0a9c81fc6a153ac69b4883c25a112a4f99f65868a5c7d1390fe0946166661338e50a9421a7012be6e26081b033e9aae70534283b64cfaff88e2" },
                { "en-CA", "a25c2c49acefe3245616ce2a4d3a616610157c4f20c70f3f4c7c7d9cdbb8ac503979ab9529cbadce9eac0e4156a54d20e0a77e9a0b38e3e40e99adbdcbe4df21" },
                { "en-GB", "0174e01c776ba57fb5ce0dc05be5976715abd77be847c56209dc4fd4792c7af0016c1b9cdcb867d597f349294d755d290c105e696b65509956e8793185a720b9" },
                { "en-US", "e1e955577c9c9d6682133384150a53bcb8824892645cd2b1811c0fdf63e844d5cc0f0b6c62a8137170da7ec44606d6b5e502f8d64b71f2d4e5d8e56b45fa20e1" },
                { "eo", "9d6b7d75e03ad68b587ac49d14e2d6fd8b6abbfff3c5b0e184e1cb96378375251578f6cd7ffb24e132b1026250e3f67cf68813ee22497fe665c8f7bc8e7a556f" },
                { "es-AR", "dfc7ca89aa67b6d7e2f0b7f22d9df79192529f143b76dc3d4be14a3d5904a9cdc2220542e9163f5aebed234e95ea559471d911535e4fe37905f06a8aee53c3ec" },
                { "es-CL", "729e80bec3a7c4429b47f3d7237b1a78834ff0147bbd29ba17856e01e3083f740dbaae4246a91b4bd39b415d169624386adb6d915fc7d56cb73e47252d2af2ec" },
                { "es-ES", "aaf20949abf500595862335846313fc40cea9725a292f5cb3ef0edf8553b8544d9fc42a0a0408feb74fd09d93c04e668efa365576eedba90b94caa9e93ed9622" },
                { "es-MX", "26c79ee8eee390b8f90e28a95d1775bf4af95faac7f5e6897f455027e537e6c776ab6c7fbe0dbd3198540d7d7b8fef3b5554f4af642055e4f115ed9caf28a54f" },
                { "et", "4382d39e5948fdb475267311649a5599c58955c886fe92c60b0ee4081e9a744679f2d2ddc6a6b09fb2ab2ce7a5b38b2e2e9a8bd98511c1c8bf4a4909c819cddb" },
                { "eu", "a72ec9c887a590bacead87c0f65882aae58cd4191d1d7db92f15bbead79a4ef9a2a47a0313a4748a0bb9ab89d52fa6d96b0b815e4170572226f3afe5f75613c8" },
                { "fa", "b0b81044b4af67a49c2337c43282dec3e989cd83f15f40b3958d80041a807cdbea7f7c3150385ecc5f6373cdb556ad8916ccf66eac4d6f63a7e86d74adeb7dc3" },
                { "ff", "5cf5908e0d920d85513feedcdfb7fd998b2337933e06b416d8f4b6b2b34dcef8fc7712c84e6f06e94242dd82da57e18b0d422eb748094f71d23aeaf0bb506993" },
                { "fi", "246b4f41b67336b0c333a3531fe641329be27744fd01937fb1fc68084b8c7ac2b2d5d184e351a12caab9b0a61ec1320044cb7b13e9a4df22a548e19ea87800f6" },
                { "fr", "34ddabbe18f4c2921a0f20ab47ad84ad89173c7a7bfea0fe1a1a3189473cadd9b9345d0537897ee70c52e7541d86f1a9140b835347077f4ca58040af862df2e4" },
                { "fur", "0af6ac819540b046cc75e0ce63417ea4fccebc29674fd8c1ca391d64876f3fe25d75d4c2f8d0588926575e1f623963f994d2d4ce5481c2f0eec4c5f8a93bfc42" },
                { "fy-NL", "09f706b05527ca494eb75a3aa83db1379db3e274a139fdb63f3f0c8c99212773e47afab0781c93fcefa32f14ec9901c3b48463c2f9891e43eeece4a5edf9b9e6" },
                { "ga-IE", "217d6e7fb4a84dde0693833866d8ff6c9358431f057c5fd856edbf9da6cfefdcc4ef1df516117052c45d0f26f2db6388183d4a07a1fc7167d78826ba738109df" },
                { "gd", "11cd6f4d14860022c5d2577e8b3a49ad1c1472c598829170c091041214e90f3d5678f921c1389c7182a6d9c312d708a517b68bcdbdf36ef296ab709ad077dbeb" },
                { "gl", "dc72a1b88ec3c47897c3231531711c10caec4e1d5d3ef8cf9b03d01ad1f13713f4ec93902c1f22695c81bee0ea94175f81dade0d1bc8dda99b3fdfecb12423a8" },
                { "gn", "237b7c30bf02347af047a84367af82e624186fbc513f34aebcec8433f674baa5144d6c0fe78f33ce7a2030cb5126f1468728149f726cd96d95e3311b781e9eae" },
                { "gu-IN", "bb4ec1d19b94f87896d2bf974a58996e503b46193d283b242153ef602e83997294f9a7f90a251b747705e44dcdf6085f9d9ee24adccd6828dd1b71a710967e48" },
                { "he", "44d293b210e72a99408323b917104fbe3d5d52e9a3570b7c1a16ef2ac401d9b5c6dc854cc6a09c7f703671202989a409bede5a260c51f7050822a3c58992d155" },
                { "hi-IN", "83e493d0eaf1522a4b56c26c4f55f6fb0b831b7e3e35c5dded3b2b1db0ad4150cca5c083ef5abd5e756be388f6169242f9a8c25f58846475c0933e165d1920b9" },
                { "hr", "f8f2cbab53e6b660267dc9e47407c0f0779034dd5db036253d8cac21036d5aa2f872d7ab31c80a6e0b40a95463c54ce074667786ce4f2eb2bca7e528bcbf818d" },
                { "hsb", "dde704ddc6bf1e54f8c30e509de4db471071219505efea47b89dbe234a1ce5145157b1bf9951dca1cd9e23c90e17a660b502a3f1222d03b431e236591d66486d" },
                { "hu", "561b1445ce78b43a24759383aa7fcfbbb32ed41ac32289024cb9cd9e4ab17013e916fbc987a3e3db48e2726347317e8f616f6c0e36ce6096ce560b3d3f8d916f" },
                { "hy-AM", "29ac69aaeb75264c3073cd43796fdce8550cba4aa892c327864bf3425ca6e657be6211f203c3eb3180ea258923491ae54729525794d603059f08e24e0a2dd375" },
                { "ia", "3fccde0dd144ce5f21b044a911af3234551b566a0538a800e62d5b8f37e9a9d31a30ba9e46d810dd9051c2e94eca7b89a1e622023ee471c11431b260c89ecd16" },
                { "id", "12ee5a15edc25bef0a6e97f47f6ddc025cf874fdd4d51a3dacf6594ad8b4496c2ff1bcda28468429e2655c5043d8728f659108130601f336dfe9db153c748454" },
                { "is", "14636c18670523835a3d9d3c17a379ed86fc6550c4f3266c11230e33eb2fd83d69f21c9ebef904d723b61a5c6a6a9e213f3183270523a45c7a31ea79cbb7e6d8" },
                { "it", "57d36eb29428d07c7372c71025cf310acd452303e5e26d4b4f1e3ff5eedddb884cb8345ceb544db4fb85b1aa925edcd855bd5555509cef029b2e62d0812f70ed" },
                { "ja", "e49cd30cad52a75702d68890365c9b8f945e4de27a315efebb4fc190f4bbe305c85517a94beff3eae3cfc78178664d55ebff52e0a4ac3741b8bf8bfa90db3ee4" },
                { "ka", "e01849e2751aa51ab5fb8e4203f3510b6598761987a6929db58f753bf927a4ef94dd0a3abd522a98c0165d986f1e2534769fbcb3d0b5f8cfe267f1bca0ea5a8c" },
                { "kab", "d1e9119c660f0af26ff77d8a2642b1294ea055162a547b1b2133060fadd68725f55a1c5006dc0740fb7bf1ce6839610e81ec11a92008df7c0956a82aeef15d8b" },
                { "kk", "b13c3eac7b6ba8818604348fcb688700be9530cce485104a01317eff28b15b29e5ca854fe9c9c3aad819bb8338903ee714ed6dc775d65fbc8afa83a7ecfa0557" },
                { "km", "68799070ea3ac1aa8a74c35677152dfcc53e4d3ba06a41e37aa0c4365211b3ac1498c70a9f59a549e22eebfd965788562346e7d6066125688a6f3661d4338a58" },
                { "kn", "549cfb19b3eefd761b833b3cbab10c909768b19a6c50159a26d3b3d14ef0bf91947ad2bff4e252f57f0f603315c5760e31c82a086353dd8c3882e9457d59649d" },
                { "ko", "b569e3195dc46e659ddd79e8f7b4fa3a436492876e2f061b3cd42715bf1f36a83c17f356c404acbfef84bef131022ae97441a4e37dccf0a2c0ad76135b68a33a" },
                { "lij", "594f13dee6781ba5543a97f675ec50ea69fd8b22f003b538b6fd84ab70df564458cd01fbabf4b2919c9530f6d9e5cd639e30790bab0478fab58903f477765f4a" },
                { "lt", "9b305a1f9d48c2c7aceea370ab1a82d22a78b91c3c8275a5c300641f7569eebd7fcb7ebe2c1f013649bb550cc786a60b6ba4de986003e0f18fba3a259c5653df" },
                { "lv", "c0899f5fcdd0248e83a4adc45ce37a12525ce8de5934c301a6e78e93425ba2626fe8f8499eb3768d5f98cd65f0c3f2fae8ac56f46c4ea5b5972ff82cb40f0d56" },
                { "mk", "6806cb0687e31e2272658acb235885cc8d1e00ec31093b65a3c08775bfeb3c4df9124786f71ead665c1eb0abd305dd54a2ad43fab155d8293bc9fedee60712c2" },
                { "mr", "e73a34c9172efaabc178b48d07ba820b2113dc59f0afffa11cde20eb2168cfb27e07b78b9aa88e5354881b3451adb5c3d135d60950667c9f468d52bd9854737f" },
                { "ms", "a9f9c4087b14554281580ce1ffb4a84150d3d9cccef1a00ecb7d575ef62822b97841a03b10bb98dfcdc76ad223d300204a93a32c304062081594f48e4dcaaca4" },
                { "my", "c3665e06ec72b68930cc27dd98ea57f06d4998a75918a05bd2017419e3ccc50b81c9945469ff9a84ecd2bf6b842fd19e6d6ded6bf6ed16fc86516f3271edccf6" },
                { "nb-NO", "de0224bdd9664ed9f7fbd102a72b13340b02fc9e6039e3b92dc7551d052781e22560fed587bbd5a19a4f1bd94283edb35b0fc1e6254153e448e2fc4368da4def" },
                { "ne-NP", "958e6de2fcfe62a7a5aa70b24cea90088b6b46fdc79e82da318cba90819659aaaf87c449684a09515d17c59da828d2ac92a64e406443ac23097e6b9497ff788a" },
                { "nl", "c5c84586c9283dce4358c8c916aff98c69c471a0babcc84c54bc408fe0a22fa92e200e89f550db71d0769e4fc53cb93e439be7d09a1c1dd04ce2934b1a7f424b" },
                { "nn-NO", "a43c9f934db5cc2727dfdfd45f1f0e6381bbefbecca4b8bf3bb341616bcdbedb7328070420a8d2cf8b3af156c83077fbe999eb80d1698d98f7be8a8b37921516" },
                { "oc", "9cc0391fa637d6fa27e2141b1c1e67a794c97a3ddca35bbe9bec51ff12af2cfc66ecb8a0cb61b4e2e09531b15073dcb7655298f538426f0ce903f80b1f4ad844" },
                { "pa-IN", "aafb2af96b4da8fc3382ad6585c5625672aadaed841d3ab7d39841c7b6aa6b364634bb7047bda4a1b589cf920430071e9303277da1496cb73582da71f82592c6" },
                { "pl", "45613c97da47b1e5571f439edd2b743014eb3e8c6ad47a1744412572c8f6a1d9a6c85dce6f00c308480e9ee414d48cf80976a34eb613e72dacfb52391c6b8f75" },
                { "pt-BR", "cf9a1bc14ee4793c4cd31d942f3595fea71485e4fa244c7b5967c645bdaa08c45d7a30b817e6fc38939218167a9b34405988a26802806e58264cdb9dc04c5853" },
                { "pt-PT", "17c82ea8b3ceb78513cdcf2bb830aeb75f667e6417adbfcbe8df3ec8e8d7edfabcfaab95c6d0fde2372dc24549b5be268452322ffd1d28a668a4334dd86fb313" },
                { "rm", "fa2e8aa286f5bbe008cb103f3314c857c16112df66775d059fe46b75f1ec594185999c0e2684312a684befc137eaf5af74f66e5c82ae639fd7e10efefe3b692e" },
                { "ro", "55105f72ef7ec86b28dc77727778fcee84049469b62a1ada7cec857db86c8a9935f1e58ef847e3466aecd8add551acf8adfe9dd6c0ed14fe59e84ab91ce997bc" },
                { "ru", "c17d7d00d838bf4f0578cae050579cf0d51f63230a5090887c74e6c8af31915653fc15bfd54da68ea1188b37ca6179c76a5a70f5cad7ec957c4575fe949c5caa" },
                { "sc", "53d97d73255e5c05369417ebb01bff973028570c65c35a53d149a9d870bb2736553bdc89c233b6916686b2f5ee8710bad402329a65fe8c7c32f34837c0441001" },
                { "sco", "35f3c8f28ca7974e3d4d1d11254fa17aac4273c9e3e985ce359e32d05e13844f65a5cc50d5480e18098935a087284dd5a78cb7114b624b1cb81c82ea4c439c1c" },
                { "si", "f9b98d3ac56535a6f60541f555a97e8ba759f485af981e767f51990e8daf18969d6fc6591171fef900ebae63822cc64148d947d6a201bbad4b40c091d7cb72c2" },
                { "sk", "0e1da3dda5af289aede7d3da485db57b7698475f3219995acb364e9852bc6d0d3eba6395124634a09f6ea610e5195a24aebd91d40e2436d4720921efee7f86b3" },
                { "sl", "2b156ff0131634493e739abe8ecb16b5a865805b01046881cbd24a5b5231b77603b966a0c546cd05cdceb884e40a0b3d9befe6d326b3c50a96b0fc9953d91a04" },
                { "son", "ed26504bb9732a4af19a686b876cc7a2a2885ddff95c3a5abed381592c34e0e79dca51986f2d01e47222e3d4f4aeef9787368bbd9c97bdd39d97af862eedd68e" },
                { "sq", "72c1ad58db7a79a35f6161b4a34692e5166943f2d25233f2f6d07777beff72f8e6844a78dd3f07e1c0dbf622faf97603398b08238593ac2789a75a452c3eeb31" },
                { "sr", "2842291f2e0d2dca8a3d954a4619e0bbff07515bff3fdaf2df2a74f7948c0bd7942fd70dedc1850c2a315bc6ad0a4ac4caef0fe56927eed065f525048340cb0d" },
                { "sv-SE", "71b3d214c2732f92bdc9d8740cf416fa0638d9f3a64b846318254c8296303b60b993e44d888182cab6a0103d061d71c59bff44069e2c553c29f9e575607e6401" },
                { "szl", "1635f0304a598f05682c1a4c911aa880c6c5a17d58827fab6d4dfae6417097eab7bd7f2b57535b1d96e5fa7037b2ea671d0a71919dfb05dcde6e91eb0a2ab4c1" },
                { "ta", "61cdb44da2757c299c0fb649beaa25f771a3bc07b40f2052b1c85c08ff1ec1b45b57c3d0097c0f33509c635950e2f70dcc2b166511354f7b900114195ed3eded" },
                { "te", "356a1474a987575d446b6214a920fed7a30f2007b18314ed09f27e12f270099be1e3151fa4d2f0d04f257d278efc973e592fd4ca96046b305e5a296c02e77b18" },
                { "tg", "d0e6af413e5e360f5e75f6ce279bc9dcecfbe71a67dff5601e1e4a173f60d07832507721159abd204d48e8d8c333f7a3207e5a686829ccc5b8a45500834328aa" },
                { "th", "67d7bb169d95e6a111a6e342b61b9e40f63ee09dab94133e499e3f752c04c2099644003b8aff0834f8edc71f7dd60f3b9bd7751a7ae71afc5b4de5021759808a" },
                { "tl", "e59925db706bc4c063e153f3fb3cbc55c94fc69b54a12b0af2e182731bcc66c8103b8a92090ec390eff37868f5a869f55aabd7d72b7dc4d5f6caa6c9624d9a9d" },
                { "tr", "0e438a42b008bafe01c56fe8b3cf9f7adc40d08825094950ef7a05727617561fd9b680c1bba5a90de3bd54f214e007b7476daa8635ee451aac0974cbd869f2a5" },
                { "trs", "06d9330b61ed7ed0bd068c3762923ab79118850a033aa214e2758e6f4d586fd105d856fd97e33df0c357037a342c452d1d1f9bcbf0d3f51670245c2853e301d1" },
                { "uk", "6c317e2e977454dad972d05a1f587a8aff0241cc17fb1f9e4bcc97e03dd167609c487f02ebf0bd16823536e3c0ec69a1b82de3634fab59e42f8fa5c6df205526" },
                { "ur", "d060177858bc09bbc45a22c00c47d396d087c280e2b2a6f1839d5b6514dad2d3bca64530002efab3513a78dd4ce574ef17f13148b7354affce23a693ea68b1d9" },
                { "uz", "3e05c66bbe0453277d1cbd9ea417b52464cf79644b90929fa8635dab0539caebece70ac6b147bcacb4df8052f39ea3dc53a09f61f116e6eeeaed238d80349421" },
                { "vi", "a85bd58b2e99315ef554d57eecdce1d6a60e9235b7fa2fe0823732b0c8a1312fe8e727d3f047b6323c3e16ad60fef7c5bae76aec322f17bc12c412995cd68fe1" },
                { "xh", "c063b04421afd4328bfbf3270b40cbdb6dc8609b124c06c058dfd7fe29c93a8456b7bfdf5b5d28856ba5e05db18a811a89fe842052e5adc989ae8fb1d68ec8b2" },
                { "zh-CN", "1331739520984a621b67333d94045dc55a57db6ab31135d59de275680b92b3e10cab9e93fef0702704ffbb493d46cb55f9da6e6e5986a8764ce15603f9cb7ddf" },
                { "zh-TW", "50a8a78a72da2a8e1f9a0e53335d2d2967b590d0882365c058b444084f95466fcf3b36f0a012b690cbfcb2804e3a6795ce60e8b76bbff1ce88426b1264067205" }
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
            const string knownVersion = "116.0.2";
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
