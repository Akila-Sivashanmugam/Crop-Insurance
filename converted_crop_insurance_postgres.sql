-- phpMyAdmin SQL Dump
-- version 2.11.6
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Mar 03, 2024 at 03:21 PM
-- Server version: 5.0.51
-- PHP Version: 5.2.6









--
-- Database: "crop_insurance"
--

-- --------------------------------------------------------

--
-- Table structure for table "ci_aadhar"
--

CREATE TABLE "ci_aadhar" (
  "id" INTEGER NOT NULL,
  "name" VARCHAR(20) NOT NULL,
  "mobile" BIGINT NOT NULL,
  "aadhar" VARCHAR(20) NOT NULL,
  "otp" VARCHAR(10) NOT NULL
) ;

--
-- Dumping data for table "ci_aadhar"
--

INSERT INTO "ci_aadhar" ("id", "name", "mobile", "aadhar", "otp") VALUES
(1, 'Kannan', 9894442716, '254681369127', '2382'),
(2, 'Ganesh', 9894442854, '359862734892', '8981'),
(3, 'Raguvaran', 8965452754, '255584148487', '4353'),
(4, 'Nisha', 8968555747, '254489684517', '7205'),
(5, 'Rishi', 9872589515, '255384148486', '2002'),
(6, 'Kumar', 7822655212, '235645781458', '6990'),
(7, 'Nirmal', 7985477864, '228945771699', ''),
(8, 'Girish', 6347829551, '299847562458', ''),
(9, 'Vignesh', 7598552418, '254489652523', ''),
(10, 'Sheela', 99855244251, '246548115765', '');

-- --------------------------------------------------------

--
-- Table structure for table "ci_admin"
--

CREATE TABLE "ci_admin" (
  "username" VARCHAR(20) NOT NULL,
  "password" VARCHAR(20) NOT NULL
) ;

--
-- Dumping data for table "ci_admin"
--

INSERT INTO "ci_admin" ("username", "password") VALUES
('admin', 'admin');

-- --------------------------------------------------------

--
-- Table structure for table "ci_apply"
--

CREATE TABLE "ci_apply" (
  "id" INTEGER NOT NULL,
  "farmer" VARCHAR(20) NOT NULL,
  "sid" INTEGER NOT NULL,
  "company" VARCHAR(20) NOT NULL,
  "aadhar" VARCHAR(20) NOT NULL,
  "name" VARCHAR(20) NOT NULL,
  "father" VARCHAR(20) NOT NULL,
  "door" VARCHAR(20) NOT NULL,
  "landmark" VARCHAR(30) NOT NULL,
  "district" VARCHAR(20) NOT NULL,
  "mandal" VARCHAR(20) NOT NULL,
  "ward" VARCHAR(20) NOT NULL,
  "mobile" BIGINT NOT NULL,
  "email" VARCHAR(40) NOT NULL,
  "ration" VARCHAR(20) NOT NULL,
  "community" VARCHAR(20) NOT NULL,
  "farmer_cat" VARCHAR(30) NOT NULL,
  "bank" VARCHAR(30) NOT NULL,
  "account" VARCHAR(20) NOT NULL,
  "branch" VARCHAR(20) NOT NULL,
  "ifsc" VARCHAR(20) NOT NULL,
  "district2" VARCHAR(20) NOT NULL,
  "mandal2" VARCHAR(20) NOT NULL,
  "ward2" VARCHAR(20) NOT NULL,
  "survey" VARCHAR(20) NOT NULL,
  "extent" VARCHAR(20) NOT NULL,
  "hectare" VARCHAR(20) NOT NULL,
  "crop_name" VARCHAR(20) NOT NULL,
  "sow_date" VARCHAR(20) NOT NULL,
  "area_sown" VARCHAR(20) NOT NULL,
  "land_doc" VARCHAR(50) NOT NULL,
  "proof_aadhar" VARCHAR(50) NOT NULL,
  "proof_address" VARCHAR(50) NOT NULL,
  "proof_income" VARCHAR(50) NOT NULL,
  "photo" VARCHAR(50) NOT NULL,
  "apply_date" VARCHAR(20) NOT NULL,
  "premium_amount" DOUBLE PRECISION NOT NULL,
  "status" INTEGER NOT NULL,
  "otp" VARCHAR(10) NOT NULL,
  "payout_st" INTEGER NOT NULL,
  "payout" DOUBLE PRECISION NOT NULL
) ;

--
-- Dumping data for table "ci_apply"
--

INSERT INTO "ci_apply" ("id", "farmer", "sid", "company", "aadhar", "name", "father", "door", "landmark", "district", "mandal", "ward", "mobile", "email", "ration", "community", "farmer_cat", "bank", "account", "branch", "ifsc", "district2", "mandal2", "ward2", "survey", "extent", "hectare", "crop_name", "sow_date", "area_sown", "land_doc", "proof_aadhar", "proof_address", "proof_income", "photo", "apply_date", "premium_amount", "status", "otp", "payout_st", "payout") VALUES
(1, 'kannan', 1, 'royal', '254681369127', 'Kannan S', 'Sakthi', '5', 'Temple', 'Thanjavur', 'Thanjavur', 'FF Nagar', 9894442716, 'kannan@gmail.com', '245955', 'BC', 'SC', '', '2389452615', 'FF Nagar', 'SB0025588', 'Thanjavur', 'Thanjavur', 'FF Nagar', '25578454', 'East', '4', 'Bajra', '2023-11-11', '10', 'A1land1.jpg', 'B1adr1.jpg', 'C1rts1.jpg', 'D1inmm.jpg', 'E1fmf.jpg', '24-02-2024', 200000, 1, '4153', 0, 0),
(2, 'ganesh', 1, 'royal', '359862734892', 'Ganesh Kumar', 'Ram', '8', 'Nagakudi', 'Thanjavur', 'Nagakudi', 'Nagakudi', 9894442854, 'ganesh@gmail.com', '5689785', 'ST', 'ST', '', '2444000361', 'Nagakudi', 'IB0002585', 'Thanjavur', 'Nagakudi', 'Nagakudi', '25487854', 'West', '10', 'Bajra', '2023-09-01', '25', 'A2land2.jpg', 'B2adr1.jpg', 'C2rts1.jpg', 'D2inmm.jpg', 'E2fmf.jpg', '25-02-2024', 500000, 1, '1451', 0, 0),
(3, 'raguvaran', 1, 'royal', '255584148487', 'Raguvaran S', 'Mani', '5/4th street', 'SM Mahal', 'Pudukkottai', 'Sendakudi', 'Sendakudi', 8965452754, 'raguvaran@gmail.com', '5478421', 'SC', 'SC', '', '36958511114', 'Sendakudi', 'CU5512014', 'Pudukkottai', 'Sendakudi', 'Sendakudi', '62115544', 'North', '2', 'Bajra', '2023-09-05', '5', 'A3land3.jpg', 'B3adr1.jpg', 'C3rts1.jpg', 'D3inmm.jpg', 'E3fmf.jpg', '25-02-2024', 200000, 1, '', 3, 200000),
(4, 'Nisha', 1, 'royal', '254489684517', 'Nisha M', 'Noor', '6/7', 'RR Road', 'Salem', 'Reddur', 'Reddur', 8965452754, 'nisha@gmail.com', '3455456', 'BC', 'ST', '', '36958511114', 'Sendakudi', 'CU5512014', 'Salem', 'Reddur', 'Reddur', '5812126', 'South', '3', 'Bajra', '2023-09-06', '7.5', 'A4land1.jpg', 'B4adr1.jpg', 'C4rts1.jpg', 'D4inmm.jpg', 'E4fmf.jpg', '25-02-2024', 300000, 1, '', 0, 0),
(5, 'rishi', 1, 'royal', '255384148486', 'Rishi Raj', 'Suresh', '6/8', 'Bus stand', 'Dindigul', 'Pallapatti', 'Pallapatti', 9872589515, 'rishi@gmail.com', '2368955', 'OC', 'ST', '', '2898850014', 'Pallapatti', 'SB002557', 'Dindigul', 'Pallapatti', 'Pallapatti', '65485544', 'East', '4', 'Bajra', '2023-09-07', '10', 'A5land1.jpg', 'B5adr1.jpg', 'C5rts1.jpg', 'D4inmm.jpg', 'E5fmf.jpg', '25-02-2024', 400000, 1, '', 0, 0),
(6, 'kumar', 1, 'royal', '235645781458', 'Kumar S', 'Raj', '12/8', 'Temple', 'Pudukkottai', 'Puravasakudi', 'Puravasakudi', 7985477864, 'kumar@gmail.com', '6254545', 'SC', 'SC', '', '2898820016', 'Puravasakudi', 'SB002559', 'Pudukottai', 'Puravasakudi', 'Puravasakudi', '65485544', 'North', '3', 'Bajra', '2023-09-10', '7.5', 'A6land1.jpg', 'B6adr1.jpg', 'C6rts1.jpg', 'D6inmm.jpg', 'E6fmf.jpg', '25-02-2024', 200000, 1, '', 3, 200000);

-- --------------------------------------------------------

--
-- Table structure for table "ci_claim"
--

CREATE TABLE "ci_claim" (
  "id" INTEGER NOT NULL,
  "farmer" VARCHAR(20) NOT NULL,
  "sid" INTEGER NOT NULL,
  "company" VARCHAR(20) NOT NULL,
  "aadhar" VARCHAR(20) NOT NULL,
  "name" VARCHAR(20) NOT NULL,
  "father" VARCHAR(20) NOT NULL,
  "address" VARCHAR(50) NOT NULL,
  "district" VARCHAR(20) NOT NULL,
  "mandal" VARCHAR(20) NOT NULL,
  "ward" VARCHAR(20) NOT NULL,
  "mobile" BIGINT NOT NULL,
  "email" VARCHAR(40) NOT NULL,
  "community" VARCHAR(20) NOT NULL,
  "bank" VARCHAR(20) NOT NULL,
  "account" VARCHAR(20) NOT NULL,
  "branch" VARCHAR(20) NOT NULL,
  "ifsc" VARCHAR(20) NOT NULL,
  "account_type" VARCHAR(30) NOT NULL,
  "loss_date" VARCHAR(20) NOT NULL,
  "loss_date2" VARCHAR(20) NOT NULL,
  "total_area" VARCHAR(20) NOT NULL,
  "crop_loss" VARCHAR(20) NOT NULL,
  "cause_loss" VARCHAR(50) NOT NULL,
  "proof1" VARCHAR(50) NOT NULL,
  "proof2" VARCHAR(50) NOT NULL,
  "claim_date" VARCHAR(20) NOT NULL,
  "status" INTEGER NOT NULL,
  "aid" INTEGER NOT NULL,
  "lat" VARCHAR(20) NOT NULL,
  "lon" VARCHAR(20) NOT NULL
) ;

--
-- Dumping data for table "ci_claim"
--

INSERT INTO "ci_claim" ("id", "farmer", "sid", "company", "aadhar", "name", "father", "address", "district", "mandal", "ward", "mobile", "email", "community", "bank", "account", "branch", "ifsc", "account_type", "loss_date", "loss_date2", "total_area", "crop_loss", "cause_loss", "proof1", "proof2", "claim_date", "status", "aid", "lat", "lon") VALUES
(1, 'kannan', 1, 'royal', '254681369127', 'Kannan S', 'Sakthi', '45,FF Nagar', 'Thanjavur', 'Thanjavur', 'FF Nagar', 42716, 'kannan@gmail.com', 'BC', 'SBI', '2389452615', 'FF Nagar', 'SB0025588', 'Crop Loan', '2023-12-01', '2023-12-05', '4', '2', '1', 'F1cff1.jpg', 'G1cff2.jpg', '24-02-2024', 1, 1, '10.795114', '79.140399');

-- --------------------------------------------------------

--
-- Table structure for table "ci_company"
--

CREATE TABLE "ci_company" (
  "id" INTEGER NOT NULL,
  "company" VARCHAR(50) NOT NULL,
  "name" VARCHAR(20) NOT NULL,
  "mobile" BIGINT NOT NULL,
  "email" VARCHAR(40) NOT NULL,
  "address" VARCHAR(50) NOT NULL,
  "district" VARCHAR(30) NOT NULL,
  "company_code" VARCHAR(30) NOT NULL,
  "license_proof" VARCHAR(50) NOT NULL,
  "username" VARCHAR(20) NOT NULL,
  "password" VARCHAR(20) NOT NULL,
  "approve_status" INTEGER NOT NULL,
  "register_date" VARCHAR(20) NOT NULL
) ;

--
-- Dumping data for table "ci_company"
--

INSERT INTO "ci_company" ("id", "company", "name", "mobile", "email", "address", "district", "company_code", "license_proof", "username", "password", "approve_status", "register_date") VALUES
(1, 'Royal Sundaram General Insurance Co. Limited', 'Ramesh', 9874562255, 'ramesh@gmail.com', '52, RR Nagar', 'Chennai', '1152', 'P1ls1.jpg', 'royal', '123456', 1, '24-02-2024');

-- --------------------------------------------------------

--
-- Table structure for table "ci_farmer"
--

CREATE TABLE "ci_farmer" (
  "id" INTEGER NOT NULL,
  "name" VARCHAR(20) NOT NULL,
  "last_name" VARCHAR(20) NOT NULL,
  "mobile" BIGINT NOT NULL,
  "email" VARCHAR(40) NOT NULL,
  "address" VARCHAR(50) NOT NULL,
  "district" VARCHAR(30) NOT NULL,
  "aadhar" VARCHAR(20) NOT NULL,
  "farmercard" VARCHAR(20) NOT NULL,
  "username" VARCHAR(20) NOT NULL,
  "password" VARCHAR(20) NOT NULL,
  "reg_date" VARCHAR(20) NOT NULL
) ;

--
-- Dumping data for table "ci_farmer"
--

INSERT INTO "ci_farmer" ("id", "name", "last_name", "mobile", "email", "address", "district", "aadhar", "farmercard", "username", "password", "reg_date") VALUES
(1, 'Kannan', 'S', 9894442716, 'kannan@gmail.com', '45,FF Nagar', 'Thanjavur', '254681369127', '2236516734641175', 'kannan', '123456', '24-02-2024'),
(2, 'Ganesh', 'Kumar', 9894442854, 'ganesh@gmail.com', 'Nagakudi', 'Thanjavur', '359862734892', '2356518334248176', 'ganesh', '123456', '25-02-2024'),
(3, 'Raguvaran', 'S', 8965452754, 'raguvaran@gmail.com', 'Sendakudi', 'Pudukottai', '255584148487', '2236516734641177', 'raguvaran', '123456', '25-02-2024'),
(4, 'Nisha', 'M', 8965452754, 'nisha@gmail.com', 'Reddur', 'Salem', '254489684517', '2236516734641178', 'nisha', '123456', '25-02-2024'),
(5, 'Rishi', 'Raj', 9872589515, 'rishi@gmail.com', 'Pallapatti', 'Dindigul', '255384148486', '2236516734641179', 'rishi', '123456', '25-02-2024'),
(6, 'Kumar', 'S', 7985477864, 'kumar@gmail.com', 'Puravasakudi', 'Pudukkottai', '235645781458', '2236516734641180', 'kumar', '123456', '25-02-2024');

-- --------------------------------------------------------

--
-- Table structure for table "ci_farmercard"
--

CREATE TABLE "ci_farmercard" (
  "id" INTEGER NOT NULL,
  "name" VARCHAR(20) NOT NULL,
  "farmercard" VARCHAR(20) NOT NULL
) ;

--
-- Dumping data for table "ci_farmercard"
--

INSERT INTO "ci_farmercard" ("id", "name", "farmercard") VALUES
(1, 'Kannan', '2236516734641175'),
(2, 'Ganesh', '2356518334248176'),
(3, 'Raguvaran', '2236516734641177'),
(4, 'Nisha', '2236516734641178'),
(5, 'Rishi', '2236516734641179'),
(6, 'Kumar', '2236516734641180'),
(7, 'Nirmal', '2236516734641181'),
(8, 'Girish', '2236516734641182'),
(9, 'Vignesh', '2236516734641183'),
(10, 'Sheela', '2236516734641184');

-- --------------------------------------------------------

--
-- Table structure for table "ci_location"
--

CREATE TABLE "ci_location" (
  "id" INTEGER NOT NULL,
  "area" VARCHAR(40) NOT NULL,
  "district" VARCHAR(40) NOT NULL,
  "lat" VARCHAR(20) NOT NULL,
  "lon" VARCHAR(20) NOT NULL
) ;

--
-- Dumping data for table "ci_location"
--

INSERT INTO "ci_location" ("id", "area", "district", "lat", "lon") VALUES
(1, 'Papanasam', 'Thanjavur', '10.924426', '79.285516'),
(2, 'Nagakudi', 'Thanjavur', '10.9731', '79.337623'),
(3, 'Sendakudi', 'Pudukottai', '10.28663', '78.928887'),
(4, 'Reddur', 'Salem', '11.762811', '77.808297'),
(5, 'Pallapatti', 'Dindigul', '10.36836', '77.947742'),
(6, 'Puravasakudi', 'Pudukottai', '10.339806', '78.867391'),
(7, 'Lakshmipuram', 'Ramanathapuram', '9.377338', '78.840002');

-- --------------------------------------------------------

--
-- Table structure for table "ci_payment"
--

CREATE TABLE "ci_payment" (
  "id" INTEGER NOT NULL,
  "company" VARCHAR(20) NOT NULL,
  "farmer" VARCHAR(20) NOT NULL,
  "sid" INTEGER NOT NULL,
  "aid" INTEGER NOT NULL,
  "amount" DOUBLE PRECISION NOT NULL,
  "pdate" VARCHAR(20) NOT NULL,
  "pay_st" INTEGER NOT NULL,
  "star" INTEGER NOT NULL
) ;

--
-- Dumping data for table "ci_payment"
--

INSERT INTO "ci_payment" ("id", "company", "farmer", "sid", "aid", "amount", "pdate", "pay_st", "star") VALUES
(1, 'Kharif', 'kannan', 1, 1, 7000, '2024-02-24', 1, 0),
(2, 'Kharif', 'kannan', 1, 1, 7000, '2023-12-20', 1, 4),
(3, 'royal', 'ganesh', 1, 2, 17500, '2023-09-10', 1, 5);

-- --------------------------------------------------------

--
-- Table structure for table "ci_query"
--

CREATE TABLE "ci_query" (
  "id" INTEGER NOT NULL,
  "farmer" VARCHAR(20) NOT NULL,
  "company" VARCHAR(20) NOT NULL,
  "farmer_query" VARCHAR(200) NOT NULL,
  "reply" VARCHAR(200) NOT NULL,
  "rdate" VARCHAR(20) NOT NULL
) ;

--
-- Dumping data for table "ci_query"
--

INSERT INTO "ci_query" ("id", "farmer", "company", "farmer_query", "reply", "rdate") VALUES
(1, 'kannan', 'royal', 'good', 'ok', '25-02-2024');

-- --------------------------------------------------------

--
-- Table structure for table "ci_scheme"
--

CREATE TABLE "ci_scheme" (
  "id" INTEGER NOT NULL,
  "company" VARCHAR(20) NOT NULL,
  "scheme" VARCHAR(100) NOT NULL,
  "season" VARCHAR(50) NOT NULL,
  "crops" VARCHAR(100) NOT NULL,
  "premium_rate" DOUBLE PRECISION NOT NULL,
  "details" TEXT NOT NULL,
  "create_date" VARCHAR(20) NOT NULL
) ;

--
-- Dumping data for table "ci_scheme"
--

INSERT INTO "ci_scheme" ("id", "company", "scheme", "season", "crops", "premium_rate", "details", "create_date") VALUES
(1, 'royal', 'NAIS Scheme', 'Kharif', 'Bajra & Oil Seeds', 3.5, '50% subsidy in premium is allowed in respect of Small & Marginal farmers, to be shared equally by the Government of India and State/UT Govt.', '24-02-2024'),
(2, 'royal', 'NAIS Scheme', 'Rabi', 'Wheat', 1.5, 'The actuarial rates shall be applied at District / Region / State level at the option of the State Govt./UT.', '24-02-2024');
