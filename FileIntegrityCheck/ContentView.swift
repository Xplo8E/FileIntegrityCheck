//
//  ContentView.swift
//  FileIntegrityCheck
//
//  Created by APPLE on 16/09/24.
//

import SwiftUI

struct ContentView: View {
    @StateObject private var integrityChecker = IntegrityChecker()
    @State private var isChecking = false

    var body: some View {
        VStack(spacing: 20) {
            Text("File Integrity Check Results")
                .font(.title)
            
            IntegrityResultView(title: "App Source Code", result: integrityChecker.appSourceCodeIntegrity)
            IntegrityResultView(title: "Provision File", result: integrityChecker.provisionFileIntegrity)
            
            Button(action: {
                isChecking = true
                integrityChecker.performChecks {
                    isChecking = false
                }
            }) {
                if isChecking {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .blue))
                } else {
                    Text("Recheck Integrity")
                        .foregroundColor(.white)
                        .padding()
                        .background(Color.blue)
                        .cornerRadius(10)
                }
            }
            .disabled(isChecking)
        }
        .padding()
        .onAppear {
            integrityChecker.performChecks {}
        }
    }
}

struct IntegrityResultView: View {
    let title: String
    let result: Bool?
    
    var body: some View {
        HStack {
            Text(title)
            Spacer()
            if let result = result {
                Image(systemName: result ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundColor(result ? .green : .red)
            } else {
                ProgressView()
            }
        }
        .padding()
        .background(Color.gray.opacity(0.1))
        .cornerRadius(10)
    }
}

#Preview {
    ContentView()
}
